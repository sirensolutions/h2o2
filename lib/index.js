'use strict';
/*eslint brace-style: [2, "1tbs"]*/

// Load modules

const Http = require('http');
const Https = require('https');
const Hoek = require('hoek');
const Joi = require('joi');
const Wreck = require('wreck');
const Boom = require('boom');

const URL = require('url');

// Declare internals

const internals = {
    agents: {}                                      // server.info.uri -> { http, https, insecure }
};


internals.defaults = {
    xforward: false,
    passThrough: false,
    redirects: false,
    timeout: 1000 * 60 * 3,                         // Timeout request after 3 minutes
    localStatePassThrough: false,                   // Pass cookies defined by the server upstream
    maxSockets: Infinity
};


internals.schema = Joi.object({
    host: Joi.string(),
    port: Joi.number().integer(),
    protocol: Joi.string().valid('http', 'https', 'http:', 'https:'),
    uri: Joi.string(),
    passThrough: Joi.boolean(),
    localStatePassThrough: Joi.boolean(),
    acceptEncoding: Joi.boolean().when('passThrough', { is: true, otherwise: Joi.forbidden() }),
    rejectUnauthorized: Joi.boolean(),
    xforward: Joi.boolean(),
    redirects: Joi.number().min(0).integer().allow(false),
    timeout: Joi.number().integer(),
    mapUri: Joi.func(),
    onResponse: Joi.func(),
    agent: Joi.object(),
    ttl: Joi.string().valid('upstream').allow(null),
    maxSockets: Joi.number().positive().allow(false),

    // added for kibi
    onBeforeSendRequest: Joi.any()
})
.xor('host', 'mapUri', 'uri')
.without('mapUri', 'port', 'protocol')
.without('uri', 'port', 'protocol');


exports.register = function (server, pluginOptions, next) {

    server.handler('kibi_proxy', internals.handler);

    server.decorate('reply', 'kibi_proxy', function (options) {

        internals.handler(this.request.route, options)(this.request, this);
    });

    return next();
};

exports.register.attributes = {
    pkg: require('../package.json')
};


internals.handler = function (route, handlerOptions) {

    Joi.assert(handlerOptions, internals.schema, 'Invalid proxy handler options (' + route.path + ')');
    Hoek.assert(!route.settings.payload || ((route.settings.payload.output === 'data' || route.settings.payload.output === 'stream') && !route.settings.payload.parse), 'Cannot proxy if payload is parsed or if output is not stream or data');
    const settings = Hoek.applyToDefaultsWithShallow(internals.defaults, handlerOptions, ['agent']);
    settings.mapUri = handlerOptions.mapUri || internals.mapUri(handlerOptions.protocol, handlerOptions.host, handlerOptions.port, handlerOptions.uri);

    // kibi: added
    const onBeforeSendRequest = handlerOptions.onBeforeSendRequest || false;

    if (settings.ttl === 'upstream') {
        settings._upstreamTtl = true;
    }

    return function (request, reply) {

        settings.mapUri(request, (err, uri, headers) => {

            if (err) {
                return reply(err);
            }

            const protocol = uri.split(':', 1)[0];

            const options = {
                headers: {},
                payload: request.payload,
                redirects: settings.redirects,
                timeout: settings.timeout,
                agent: internals.agent(protocol, settings, request.connection)
            };

            const bind = request.route.settings.bind;

            if (settings.passThrough) {
                options.headers = Hoek.clone(request.headers);
                delete options.headers.host;

                if (settings.acceptEncoding === false) {                    // Defaults to true
                    delete options.headers['accept-encoding'];
                }

                if (options.headers.cookie) {
                    delete options.headers.cookie;

                    const cookieHeader = request.connection.states.passThrough(request.headers.cookie, settings.localStatePassThrough);
                    if (cookieHeader) {
                        if (typeof cookieHeader !== 'string') {
                            return reply(cookieHeader);                     // Error
                        }

                        options.headers.cookie = cookieHeader;
                    }
                }
            }

            if (headers) {
                Hoek.merge(options.headers, headers);
            }

            if (settings.xforward &&
                request.info.remotePort &&
                request.info.remoteAddress) {
                options.headers['x-forwarded-for'] = (options.headers['x-forwarded-for'] ? options.headers['x-forwarded-for'] + ',' : '') + request.info.remoteAddress;
                options.headers['x-forwarded-port'] = (options.headers['x-forwarded-port'] ? options.headers['x-forwarded-port'] + ',' : '') + request.info.remotePort;
                options.headers['x-forwarded-proto'] = (options.headers['x-forwarded-proto'] ? options.headers['x-forwarded-proto'] + ',' : '') + request.connection.info.protocol;
                options.headers['x-forwarded-host'] = (options.headers['x-forwarded-host'] ? options.headers['x-forwarded-host'] + ',' : '') + request.info.host;
            }

            const contentType = request.headers['content-type'];
            if (contentType) {
                options.headers['content-type'] = contentType;
            }

            const _onError = function (err, res, ttl) {

                if (settings.onResponse) {
                    return settings.onResponse.call(bind, err, res, request, reply, settings, ttl);
                }

                return reply(err);
            };

            // Encoding request path
            const _encodeURL = (url) => {
                if (decodeURI(url) === url) {
                    url = encodeURI(url);
                }
                return url;
            };
            uri = _encodeURL(uri);

            const _sendRequest = function () {

                Wreck.request(request.method, uri, options, (err, res) => {

                    let ttl = null;

                    if (err) {
                        if (settings.onResponse) {
                            return settings.onResponse.call(bind, err, res, request, reply, settings, ttl);
                        }
                        return reply(err);
                    }

                    if (settings._upstreamTtl) {
                        const cacheControlHeader = res.headers['cache-control'];
                        if (cacheControlHeader) {
                            const cacheControl = Wreck.parseCacheControl(cacheControlHeader);
                            if (cacheControl) {
                                ttl = cacheControl['max-age'] * 1000;
                            }
                        }
                    }

                    if (settings.onResponse) {
                        return settings.onResponse.call(bind, null, res, request, reply, settings, ttl);
                    }

                    return reply(res)
                    .ttl(ttl)
                    .code(res.statusCode)
                    .passThrough(!!settings.passThrough);   // Default to false
                });
            };

            // Send request
            if (onBeforeSendRequest) {
                onBeforeSendRequest(request)
                  .then((requestUpdates) => {
                    Hoek.merge(options, requestUpdates);

                    // Note:
                    // Below change is to mitigate federate bug - unnecessary overhead in schema computation phase
                    // on indices with many shards
                    //
                    // We do NOT send requests without joins to /siren endpoint
                    if (requestUpdates.payload) {
                        const payload = requestUpdates.payload.toString();
                        const myUri = URL.parse(uri);
                        let containJoin = false;
                        let isSearchOrMsearch = false;

                        const reviver = function (key, value) {
                            if (key === 'join' && value.on !== undefined) {
                                containJoin = true;
                            }
                            return value;
                        };

                        if (myUri.pathname && myUri.pathname.indexOf('/_msearch') !== -1) {
                          isSearchOrMsearch = true;
                          const lines = payload.split("\n");
                          for (let i = 1; i < lines.length - 1; i = i + 2 ) {
                            if (containJoin) {
                                continue;
                            }
                            if (lines[i] !== '') {
                                try {
                                  JSON.parse(lines[i], reviver);
                                } catch (e) {
                                  console.log('Error parsing _msearch request payload [' + lines[i] + ']', e);
                                }
                            }
                          }
                        } else if (myUri.pathname && myUri.pathname.indexOf('/_search') !== -1){
                          isSearchOrMsearch = true;
                          if (payload !== '') {
                              try {
                                JSON.parse(payload, reviver);
                              } catch (e) {
                                console.log('Error parsing _search request payload [' + payload + ']', e);
                              }
                          }
                        }

                        if (isSearchOrMsearch && !containJoin) {
                            const pathWithNoSiren = myUri.pathname.replace(/^\/siren\//, '/');
                            myUri.pathname = pathWithNoSiren;

                            let search = myUri.search;
                            if (search && search.indexOf('preference')) {
                                if (search.startsWith('?')) {
                                    search = search.substring(1);
                                }
                                const pairs = search.split('&');
                                for (let i = pairs.length - 1; i >= 0; i--) {
                                    if (pairs[i].startsWith('preference=')) {
                                        pairs.splice(i, 1);
                                    }
                                }
                                search = pairs.join('&');
                                myUri.search = search;
                            }

                            try {
                                uri = URL.format(myUri);
                            } catch (e) {
                                console.log('Error when formatting the URL', e);
                            }
                        }
                    }
                    // end of mitigation code

                    _sendRequest();
                  })
                  .catch((err) => {
                    let msg = 'Failed request';
                    if (err.message) {
                        msg = err.message;
                    }
                    return _onError(Boom.badRequest(msg, err));
                });
            } else {
                _sendRequest();
            }
        });
    };
};


internals.handler.defaults = function (method) {

    const payload = method !== 'get' && method !== 'head';
    return payload ? {
        payload: {
            output: 'stream',
            parse: false
        }
    } : null;
};


internals.mapUri = function (protocol, host, port, uri) {

    if (uri) {
        return function (request, next) {

            if (uri.indexOf('{') === -1) {
                return next(null, uri);
            }

            let address = uri.replace(/{protocol}/g, request.connection.info.protocol)
                             .replace(/{host}/g, request.connection.info.host)
                             .replace(/{port}/g, request.connection.info.port)
                             .replace(/{path}/g, request.url.path);

            Object.keys(request.params).forEach((key) => {

                const re = new RegExp(`{${key}}`,'g');
                address = address.replace(re,request.params[key]);
            });

            return next(null, address);
        };
    }

    if (protocol && protocol[protocol.length - 1] !== ':') {

        protocol += ':';
    }

    protocol = protocol || 'http:';
    port = port || (protocol === 'http:' ? 80 : 443);
    const baseUrl = protocol + '//' + host + ':' + port;

    return function (request, next) {

        return next(null, baseUrl + request.path + (request.url.search || ''));
    };
};


internals.agent = function (protocol, settings, connection) {

    if (settings.agent) {
        return settings.agent;
    }

    if (settings.maxSockets === false) {
        return undefined;
    }

    internals.agents[connection.info.uri] = internals.agents[connection.info.uri] || {};
    const agents = internals.agents[connection.info.uri];

    const type = (protocol === 'http' ? 'http' : (settings.rejectUnauthorized === false ? 'insecure' : 'https'));
    if (!agents[type]) {
        agents[type] = (type === 'http' ? new Http.Agent() : (type === 'https' ? new Https.Agent() : new Https.Agent({ rejectUnauthorized: false })));
        agents[type].maxSockets = settings.maxSockets;
    }

    return agents[type];
};
