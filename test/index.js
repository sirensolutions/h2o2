'use strict';
// Load modules

const Fs = require('fs');
const Http = require('http');
const Net = require('net');
const Zlib = require('zlib');
const Boom = require('boom');
const Code = require('code');
const H2o2 = require('..');
const Hapi = require('hapi');
const Hoek = require('hoek');
const Lab = require('lab');
const Wreck = require('wreck');


// Declare internals

const internals = {};


// Test shortcuts

const lab = exports.lab = Lab.script();
const describe = lab.describe;
const it = lab.it;
const expect = Code.expect;


describe('H2o2', () => {

    const tlsOptions = {
        key: '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0UqyXDCqWDKpoNQQK/fdr0OkG4gW6DUafxdufH9GmkX/zoKz\ng/SFLrPipzSGINKWtyMvo7mPjXqqVgE10LDI3VFV8IR6fnART+AF8CW5HMBPGt/s\nfQW4W4puvBHkBxWSW1EvbecgNEIS9hTGvHXkFzm4xJ2e9DHp2xoVAjREC73B7JbF\nhc5ZGGchKw+CFmAiNysU0DmBgQcac0eg2pWoT+YGmTeQj6sRXO67n2xy/hA1DuN6\nA4WBK3wM3O4BnTG0dNbWUEbe7yAbV5gEyq57GhJIeYxRvveVDaX90LoAqM4cUH06\n6rciON0UbDHV2LP/JaH5jzBjUyCnKLLo5snlbwIDAQABAoIBAQDJm7YC3pJJUcxb\nc8x8PlHbUkJUjxzZ5MW4Zb71yLkfRYzsxrTcyQA+g+QzA4KtPY8XrZpnkgm51M8e\n+B16AcIMiBxMC6HgCF503i16LyyJiKrrDYfGy2rTK6AOJQHO3TXWJ3eT3BAGpxuS\n12K2Cq6EvQLCy79iJm7Ks+5G6EggMZPfCVdEhffRm2Epl4T7LpIAqWiUDcDfS05n\nNNfAGxxvALPn+D+kzcSF6hpmCVrFVTf9ouhvnr+0DpIIVPwSK/REAF3Ux5SQvFuL\njPmh3bGwfRtcC5d21QNrHdoBVSN2UBLmbHUpBUcOBI8FyivAWJhRfKnhTvXMFG8L\nwaXB51IZAoGBAP/E3uz6zCyN7l2j09wmbyNOi1AKvr1WSmuBJveITouwblnRSdvc\nsYm4YYE0Vb94AG4n7JIfZLKtTN0xvnCo8tYjrdwMJyGfEfMGCQQ9MpOBXAkVVZvP\ne2k4zHNNsfvSc38UNSt7K0HkVuH5BkRBQeskcsyMeu0qK4wQwdtiCoBDAoGBANF7\nFMppYxSW4ir7Jvkh0P8bP/Z7AtaSmkX7iMmUYT+gMFB5EKqFTQjNQgSJxS/uHVDE\nSC5co8WGHnRk7YH2Pp+Ty1fHfXNWyoOOzNEWvg6CFeMHW2o+/qZd4Z5Fep6qCLaa\nFvzWWC2S5YslEaaP8DQ74aAX4o+/TECrxi0z2lllAoGAdRB6qCSyRsI/k4Rkd6Lv\nw00z3lLMsoRIU6QtXaZ5rN335Awyrfr5F3vYxPZbOOOH7uM/GDJeOJmxUJxv+cia\nPQDflpPJZU4VPRJKFjKcb38JzO6C3Gm+po5kpXGuQQA19LgfDeO2DNaiHZOJFrx3\nm1R3Zr/1k491lwokcHETNVkCgYBPLjrZl6Q/8BhlLrG4kbOx+dbfj/euq5NsyHsX\n1uI7bo1Una5TBjfsD8nYdUr3pwWltcui2pl83Ak+7bdo3G8nWnIOJ/WfVzsNJzj7\n/6CvUzR6sBk5u739nJbfgFutBZBtlSkDQPHrqA7j3Ysibl3ZIJlULjMRKrnj6Ans\npCDwkQKBgQCM7gu3p7veYwCZaxqDMz5/GGFUB1My7sK0hcT7/oH61yw3O8pOekee\nuctI1R3NOudn1cs5TAy/aypgLDYTUGQTiBRILeMiZnOrvQQB9cEf7TFgDoRNCcDs\nV/ZWiegVB/WY7H0BkCekuq5bHwjgtJTpvHGqQ9YD7RhE8RSYOhdQ/Q==\n-----END RSA PRIVATE KEY-----\n',
        cert: '-----BEGIN CERTIFICATE-----\nMIIDBjCCAe4CCQDvLNml6smHlTANBgkqhkiG9w0BAQUFADBFMQswCQYDVQQGEwJV\nUzETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0\ncyBQdHkgTHRkMB4XDTE0MDEyNTIxMjIxOFoXDTE1MDEyNTIxMjIxOFowRTELMAkG\nA1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0\nIFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\nANFKslwwqlgyqaDUECv33a9DpBuIFug1Gn8Xbnx/RppF/86Cs4P0hS6z4qc0hiDS\nlrcjL6O5j416qlYBNdCwyN1RVfCEen5wEU/gBfAluRzATxrf7H0FuFuKbrwR5AcV\nkltRL23nIDRCEvYUxrx15Bc5uMSdnvQx6dsaFQI0RAu9weyWxYXOWRhnISsPghZg\nIjcrFNA5gYEHGnNHoNqVqE/mBpk3kI+rEVzuu59scv4QNQ7jegOFgSt8DNzuAZ0x\ntHTW1lBG3u8gG1eYBMquexoSSHmMUb73lQ2l/dC6AKjOHFB9Ouq3IjjdFGwx1diz\n/yWh+Y8wY1Mgpyiy6ObJ5W8CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAoSc6Skb4\ng1e0ZqPKXBV2qbx7hlqIyYpubCl1rDiEdVzqYYZEwmst36fJRRrVaFuAM/1DYAmT\nWMhU+yTfA+vCS4tql9b9zUhPw/IDHpBDWyR01spoZFBF/hE1MGNpCSXXsAbmCiVf\naxrIgR2DNketbDxkQx671KwF1+1JOMo9ffXp+OhuRo5NaGIxhTsZ+f/MA4y084Aj\nDI39av50sTRTWWShlN+J7PtdQVA5SZD97oYbeUeL7gI18kAJww9eUdmT0nEjcwKs\nxsQT1fyKbo7AlZBY4KSlUMuGnn0VnAsB9b+LxtXlDfnjyM8bVQx1uAfRo0DO8p/5\n3J5DTjAU55deBQ==\n-----END CERTIFICATE-----\n'
    };

    const provisionServer = function (options) {

        const server = new Hapi.Server();
        server.connection(options);
        server.register(H2o2, Hoek.ignore);
        return server;
    };

    it('overrides maxSockets', { parallel: false }, (done) => {

        const orig = Wreck.request;
        Wreck.request = function (method, uri, options, callback) {

            Wreck.request = orig;
            expect(options.agent.maxSockets).to.equal(213);
            done();
        };

        const server = provisionServer();
        server.route({ method: 'GET', path: '/', handler: { kibi_proxy: { host: 'localhost', maxSockets: 213 } } });
        server.inject('/', (res) => { });
    });

    it('uses node default with maxSockets set to false', { parallel: false }, (done) => {

        const orig = Wreck.request;
        Wreck.request = function (method, uri, options, callback) {

            Wreck.request = orig;
            expect(options.agent).to.equal(undefined);
            done();
        };

        const server = provisionServer();
        server.route({ method: 'GET', path: '/', handler: { kibi_proxy: { host: 'localhost', maxSockets: false } } });
        server.inject('/', (res) => { });
    });

    it('forwards on the response when making a GET request', (done) => {

        const profile = function (request, reply) {

            reply({ id: 'fa0dbda9b1b', name: 'John Doe' }).state('test', '123');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/profile', handler: profile, config: { cache: { expiresIn: 2000 } } });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/profile', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, xforward: true, passThrough: true } } });
            server.state('auto', { autoValue: 'xyz' });

            server.inject('/profile', (response) => {

                expect(response.statusCode).to.equal(200);
                expect(response.payload).to.contain('John Doe');
                expect(response.headers['set-cookie']).to.equal(['test=123', 'auto=xyz']);
                expect(response.headers['cache-control']).to.equal('max-age=2, must-revalidate, private');

                server.inject('/profile', (res) => {

                    expect(res.statusCode).to.equal(200);
                    expect(res.payload).to.contain('John Doe');
                    done();
                });
            });
        });
    });

    it('throws when used with explicit route payload config other than data or steam', (done) => {

        const server = provisionServer();
        expect(() => {

            server.route({
                method: 'POST',
                path: '/',
                config: {
                    handler: {
                        kibi_proxy: { host: 'example.com' }
                    },
                    payload: {
                        output: 'file'
                    }
                }
            });
        }).to.throw('Cannot proxy if payload is parsed or if output is not stream or data');
        done();
    });

    it('throws when setup with invalid options', (done) => {

        const server = provisionServer();
        expect(() => {

            server.route({
                method: 'POST',
                path: '/',
                config: {
                    handler: {
                        kibi_proxy: { some: 'key' }
                    }
                }
            });
        }).to.throw(/\"value\" must contain at least one of \[host, mapUri, uri\]/);
        done();
    });

    it('throws when used with explicit route payload parse config set to false', (done) => {

        const server = provisionServer();
        expect(() => {

            server.route({
                method: 'POST',
                path: '/',
                config: {
                    handler: {
                        kibi_proxy: { host: 'example.com' }
                    },
                    payload: {
                        parse: true
                    }
                }
            });
        }).to.throw('Cannot proxy if payload is parsed or if output is not stream or data');
        done();
    });

    it('allows when used with explicit route payload output data config', (done) => {

        const server = provisionServer();
        expect(() => {

            server.route({
                method: 'POST',
                path: '/',
                config: {
                    handler: {
                        kibi_proxy: { host: 'example.com' }
                    },
                    payload: {
                        output: 'data'
                    }
                }
            });
        }).to.not.throw();
        done();
    });

    it('uses protocol without ":"', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            }
        });

        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, protocol: 'http' } } });

            server.inject('/', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.equal('ok');
                done();
            });
        });
    });

    it('forwards upstream headers', (done) => {

        const headers = function (request, reply) {

            reply({ status: 'success' })
                .header('Custom1', 'custom header value 1')
                .header('X-Custom2', 'custom header value 2');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/headers', handler: headers });
        upstream.start(() => {

            const server = provisionServer({ routes: { cors: true } });
            server.route({ method: 'GET', path: '/headers', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, passThrough: true } } });

            server.inject('/headers', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.equal('{\"status\":\"success\"}');
                expect(res.headers.custom1).to.equal('custom header value 1');
                expect(res.headers['x-custom2']).to.equal('custom header value 2');
                done();
            });
        });
    });

    // it('overrides upstream cors headers', (done) => {
    //
    //     const headers = function (request, reply) {
    //
    //         reply().header('access-control-allow-headers', 'Invalid, List, Of, Values');
    //     };
    //
    //     const upstream = new Hapi.Server();
    //     upstream.connection();
    //     upstream.route({ method: 'GET', path: '/', handler: headers });
    //     upstream.start(function () {
    //
    //         const server = provisionServer({ routes: { cors: { credentials: true } } });
    //         server.route({ method: 'GET', path: '/', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, passThrough: true } } });
    //
    //         server.inject('/', (res) => {
    //
    //             expect(res.headers['access-control-allow-headers']).to.equal('Invalid, List, Of, Values');
    //             done();
    //         });
    //     });
    // });

    it('merges upstream headers', (done) => {

        const headers = function (request, reply) {

            reply({ status: 'success' })
                .vary('X-Custom3');
        };

        const onResponse = function (err, res, request, reply, settings, ttl) {

            expect(err).to.be.null();
            reply(res).vary('Something');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/headers', handler: headers });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/headers', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, passThrough: true, onResponse } } });

            server.inject({ url: '/headers', headers: { 'accept-encoding': 'gzip' } }, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.headers.vary).to.equal('X-Custom3,accept-encoding,Something');
                done();
            });
        });
    });

    it('forwards gzipped content', (done) => {

        const gzipHandler = function (request, reply) {

            reply('123456789012345678901234567890123456789012345678901234567890');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/gzip', handler: gzipHandler });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/gzip', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, passThrough: true } } });

            Zlib.gzip(new Buffer('123456789012345678901234567890123456789012345678901234567890'), (err, zipped) => {

                expect(err).to.not.exist();

                server.inject({ url: '/gzip', headers: { 'accept-encoding': 'gzip' } }, (res) => {

                    expect(res.statusCode).to.equal(200);
                    expect(res.rawPayload).to.equal(zipped);
                    done();
                });
            });
        });
    });

    it('forwards gzipped stream', (done) => {

        const gzipStreamHandler = function (request, reply) {

            reply.file(__dirname + '/../package.json');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.register(require('inert'), Hoek.ignore);
        upstream.route({ method: 'GET', path: '/gzipstream', handler: gzipStreamHandler });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/gzipstream', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, passThrough: true } } });

            server.inject({ url: '/gzipstream', headers: { 'accept-encoding': 'gzip' } }, (res) => {

                expect(res.statusCode).to.equal(200);

                Fs.readFile(__dirname + '/../package.json', { encoding: 'utf8' }, (err, file) => {

                    expect(err).to.be.null();
                    Zlib.unzip(res.rawPayload, (err, unzipped) => {

                        expect(err).to.not.exist();
                        expect(unzipped.toString('utf8')).to.equal(file);
                        done();
                    });
                });
            });
        });
    });

    it('does not forward upstream headers without passThrough', (done) => {

        const headers = function (request, reply) {

            reply({ status: 'success' })
                .header('Custom1', 'custom header value 1')
                .header('X-Custom2', 'custom header value 2')
                .header('access-control-allow-headers', 'Invalid, List, Of, Values');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/noHeaders', handler: headers });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/noHeaders', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port } } });

            server.inject('/noHeaders', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.equal('{\"status\":\"success\"}');
                expect(res.headers.custom1).to.not.exist();
                expect(res.headers['x-custom2']).to.not.exist();
                done();
            });
        });
    });

    it('request a cached proxy route', (done) => {

        let activeCount = 0;
        const activeItem = function (request, reply) {

            reply({
                id: '55cf687663',
                name: 'Active Items',
                count: activeCount++
            });
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/item', handler: activeItem });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/item', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, protocol: 'http:' } }, config: { cache: { expiresIn: 500 } } });

            server.inject('/item', (response) => {

                expect(response.statusCode).to.equal(200);
                expect(response.payload).to.contain('Active Items');
                const counter = response.result.count;

                server.inject('/item', (res) => {

                    expect(res.statusCode).to.equal(200);
                    expect(res.result.count).to.equal(counter);
                    done();
                });
            });
        });
    });

    it('forwards on the status code when making a POST request', (done) => {

        const item = function (request, reply) {

            reply({ id: '55cf687663', name: 'Items' }).created('http://example.com');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'POST', path: '/item', handler: item });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'POST', path: '/item', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port } } });

            server.inject({ url: '/item', method: 'POST' }, (res) => {

                expect(res.statusCode).to.equal(201);
                expect(res.payload).to.contain('Items');
                done();
            });
        });
    });

    it('sends the correct status code when a request is unauthorized', (done) => {

        const unauthorized = function (request, reply) {

            reply(Boom.unauthorized('Not authorized'));
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/unauthorized', handler: unauthorized });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/unauthorized', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port } }, config: { cache: { expiresIn: 500 } } });

            server.inject('/unauthorized', (res) => {

                expect(res.statusCode).to.equal(401);
                done();
            });
        });
    });

    it('sends a 404 status code when a proxied route does not exist', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'POST', path: '/notfound', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port } } });

            server.inject('/notfound', (res) => {

                expect(res.statusCode).to.equal(404);
                done();
            });
        });
    });

    it('overrides status code when a custom onResponse returns an error', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.start(() => {

            const onResponseWithError = function (err, res, request, reply, settings, ttl) {

                expect(err).to.be.null();
                reply(Boom.forbidden('Forbidden'));
            };

            const server = provisionServer();
            server.route({ method: 'GET', path: '/onResponseError', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, onResponse: onResponseWithError } } });

            server.inject('/onResponseError', (res) => {

                expect(res.statusCode).to.equal(403);
                done();
            });
        });
    });

    it('adds cookie to response', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.start(() => {

            const on = function (err, res, request, reply, settings, ttl) {

                expect(err).to.be.null();
                reply(res).state('a', 'b');
            };

            const server = provisionServer();
            server.route({ method: 'GET', path: '/', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, onResponse: on } } });

            server.inject('/', (res) => {

                expect(res.statusCode).to.equal(404);
                expect(res.headers['set-cookie'][0]).to.equal('a=b');
                done();
            });
        });
    });

    it('binds onResponse to route bind config', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.start(() => {

            const onResponseWithError = function (err, res, request, reply, settings, ttl) {

                expect(err).to.be.null();
                reply(this.c);
            };

            const handler = {
                kibi_proxy: {
                    host: 'localhost',
                    port: upstream.info.port,
                    onResponse: onResponseWithError
                }
            };

            const server = provisionServer();
            server.route({ method: 'GET', path: '/onResponseError', config: { handler, bind: { c: 6 } } });

            server.inject('/onResponseError', (res) => {

                expect(res.result).to.equal(6);
                done();
            });
        });
    });

    it('binds onResponse to route bind config in plugin', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.start(() => {

            const plugin = function (server, options, next) {

                const onResponseWithError = function (err, res, request, reply, settings, ttl) {

                    expect(err).to.be.null();
                    reply(this.c);
                };

                const handler = {
                    kibi_proxy: {
                        host: 'localhost',
                        port: upstream.info.port,
                        onResponse: onResponseWithError
                    }
                };

                server.route({ method: 'GET', path: '/', config: { handler, bind: { c: 6 } } });
                return next();
            };

            plugin.attributes = {
                name: 'test'
            };

            const server = provisionServer();

            server.register(plugin, (err) => {

                expect(err).to.not.exist();

                server.inject('/', (res) => {

                    expect(res.result).to.equal(6);
                    done();
                });
            });
        });
    });

    it('binds onResponse to plugin bind', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.start(() => {

            const plugin = function (server, options, next) {

                const onResponseWithError = function (err, res, request, reply, settings, ttl) {

                    expect(err).to.be.null();
                    reply(this.c);
                };

                const handler = {
                    kibi_proxy: {
                        host: 'localhost',
                        port: upstream.info.port,
                        onResponse: onResponseWithError
                    }
                };

                server.bind({ c: 7 });
                server.route({ method: 'GET', path: '/', config: { handler } });
                return next();
            };

            plugin.attributes = {
                name: 'test'
            };

            const server = provisionServer();

            server.register(plugin, (err) => {

                expect(err).to.not.exist();

                server.inject('/', (res) => {

                    expect(res.result).to.equal(7);
                    done();
                });
            });
        });
    });

    it('binds onResponse to route bind config in plugin when plugin also has bind', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.start(() => {

            const plugin = function (server, options, next) {

                const onResponseWithError = function (err, res, request, reply, settings, ttl) {

                    expect(err).to.be.null();
                    reply(this.c);
                };

                const handler = {
                    kibi_proxy: {
                        host: 'localhost',
                        port: upstream.info.port,
                        onResponse: onResponseWithError
                    }
                };

                server.bind({ c: 7 });
                server.route({ method: 'GET', path: '/', config: { handler, bind: { c: 4 } } });
                return next();
            };

            plugin.attributes = {
                name: 'test'
            };

            const server = provisionServer();

            server.register(plugin, (err) => {

                expect(err).to.not.exist();

                server.inject('/', (res) => {

                    expect(res.result).to.equal(4);
                    done();
                });
            });
        });
    });

    it('calls the onResponse function if the upstream is unreachable', (done) => {

        const dummy = new Hapi.Server();
        dummy.connection();
        dummy.start(() => {

            const dummyPort = dummy.info.port;
            dummy.stop(Hoek.ignore);

            const failureResponse = function (err, res, request, reply, settings, ttl) {

                reply(err);
            };

            const server = provisionServer();
            server.route({ method: 'GET', path: '/failureResponse', handler: { kibi_proxy: { host: 'localhost', port: dummyPort, onResponse: failureResponse } }, config: { cache: { expiresIn: 500 } } });

            server.inject('/failureResponse', (res) => {

                expect(res.statusCode).to.equal(502);
                done();
            });
        });
    });

    it('sets x-forwarded-* headers', (done) => {

        const handler = function (request, reply) {

            reply(request.raw.req.headers);
        };

        const host = '127.0.0.1';

        const upstream = new Hapi.Server();
        upstream.connection({
            host
        });
        upstream.route({ method: 'GET', path: '/', handler });
        upstream.start(() => {

            const server = provisionServer({
                host,
                tls: tlsOptions
            });

            server.route({
                method: 'GET',
                path: '/',
                handler: {
                    kibi_proxy: {
                        host: upstream.info.host,
                        port: upstream.info.port,
                        protocol: 'http',
                        xforward: true
                    }
                }
            });

            server.start(() => {

                const requestProtocol = 'https';

                Wreck.get(`${requestProtocol}://${server.info.host}:${server.info.port}/`, {
                    rejectUnauthorized: false
                }, (err, res, body) => {

                    expect(err).to.be.null();
                    expect(res.statusCode).to.equal(200);
                    const result = JSON.parse(body);

                    const expectedClientAddress = '127.0.0.1';
                    const expectedClientAddressAndPort = expectedClientAddress + ':' + server.info.port;
                    if (Net.isIPv6(server.listener.address().address)) {
                        expectedClientAddress = '::ffff:127.0.0.1';
                        expectedClientAddressAndPort = '[' + expectedClientAddress + ']:' + server.info.port;
                    }

                    expect(result['x-forwarded-for']).to.equal(expectedClientAddress);
                    expect(result['x-forwarded-port']).to.match(/\d+/);
                    expect(result['x-forwarded-proto']).to.equal(requestProtocol);
                    expect(result['x-forwarded-host']).to.equal(expectedClientAddressAndPort);

                    server.stop(Hoek.ignore);
                    upstream.stop(Hoek.ignore);
                    done();
                });
            });
        });
    });

    it('adds x-forwarded-* headers to existing', (done) => {

        const handler = function (request, reply) {

            reply(request.raw.req.headers);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/', handler });
        upstream.start(() => {

            const mapUri = function (request, callback) {

                const headers = {
                    'x-forwarded-for': 'testhost',
                    'x-forwarded-port': 1337,
                    'x-forwarded-proto': 'https',
                    'x-forwarded-host': 'example.com'
                };

                return callback(null, 'http://127.0.0.1:' + upstream.info.port + '/', headers);
            };

            const server = provisionServer({ host: '127.0.0.1' });
            server.route({ method: 'GET', path: '/', handler: { kibi_proxy: { mapUri, xforward: true } } });

            server.start(() => {

                Wreck.get('http://127.0.0.1:' + server.info.port + '/', (err, res, body) => {

                    expect(err).to.be.null();
                    expect(res.statusCode).to.equal(200);
                    const result = JSON.parse(body);

                    const expectedClientAddress = '127.0.0.1';
                    const expectedClientAddressAndPort = expectedClientAddress + ':' + server.info.port;
                    if (Net.isIPv6(server.listener.address().address)) {
                        expectedClientAddress = '::ffff:127.0.0.1';
                        expectedClientAddressAndPort = '[' + expectedClientAddress + ']:' + server.info.port;
                    }

                    expect(result['x-forwarded-for']).to.equal('testhost,' + expectedClientAddress);
                    expect(result['x-forwarded-port']).to.match(/1337\,\d+/);
                    expect(result['x-forwarded-proto']).to.equal('https,http');
                    expect(result['x-forwarded-host']).to.equal('example.com,' + expectedClientAddressAndPort);
                    server.stop(Hoek.ignore);
                    upstream.stop(Hoek.ignore);
                    done();
                });
            });
        });
    });

    it('does not clobber existing x-forwarded-* headers', (done) => {

        const handler = function (request, reply) {

            reply(request.raw.req.headers);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/', handler });
        upstream.start(() => {

            const mapUri = function (request, callback) {

                const headers = {
                    'x-forwarded-for': 'testhost',
                    'x-forwarded-port': 1337,
                    'x-forwarded-proto': 'https',
                    'x-forwarded-host': 'example.com'
                };

                return callback(null, 'http://127.0.0.1:' + upstream.info.port + '/', headers);
            };

            const server = provisionServer();
            server.route({ method: 'GET', path: '/', handler: { kibi_proxy: { mapUri, xforward: true } } });

            server.inject('/', (res) => {

                expect(res.statusCode).to.equal(200);
                const result = JSON.parse(res.payload);
                expect(result['x-forwarded-for']).to.equal('testhost');
                expect(result['x-forwarded-port']).to.equal('1337');
                expect(result['x-forwarded-proto']).to.equal('https');
                expect(result['x-forwarded-host']).to.equal('example.com');
                done();
            });
        });
    });

    it('forwards on a POST body', (done) => {

        const echoPostBody = function (request, reply) {

            reply(request.payload.echo + request.raw.req.headers['x-super-special']);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'POST', path: '/echo', handler: echoPostBody });
        upstream.start(() => {

            const mapUri = function (request, callback) {

                return callback(null, 'http://127.0.0.1:' + upstream.info.port + request.path + (request.url.search || ''), { 'x-super-special': '@' });
            };

            const server = provisionServer();
            server.route({ method: 'POST', path: '/echo', handler: { kibi_proxy: { mapUri } } });

            server.inject({ url: '/echo', method: 'POST', payload: '{"echo":true}' }, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.equal('true@');
                done();
            });
        });
    });

    it('replies with an error when it occurs in mapUri', (done) => {

        const mapUriWithError = function (request, callback) {

            return callback(new Error('myerror'));
        };

        const server = provisionServer();
        server.route({ method: 'GET', path: '/maperror', handler: { kibi_proxy: { mapUri: mapUriWithError } } });

        server.inject('/maperror', (res) => {

            expect(res.statusCode).to.equal(500);
            done();
        });
    });

    it('maxs out redirects to same endpoint', (done) => {

        const redirectHandler = function (request, reply) {

            reply.redirect('/redirect?x=1');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/redirect', handler: redirectHandler });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/redirect', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, passThrough: true, redirects: 2 } } });

            server.inject('/redirect?x=1', (res) => {

                expect(res.statusCode).to.equal(502);
                done();
            });
        });
    });

    it('errors on redirect missing location header', (done) => {

        const redirectHandler = function (request, reply) {

            reply().code(302);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/redirect', handler: redirectHandler });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/redirect', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, passThrough: true, redirects: 2 } } });

            server.inject('/redirect?x=3', (res) => {

                expect(res.statusCode).to.equal(502);
                done();
            });
        });
    });

    it('errors on redirection to bad host', (done) => {

        const server = provisionServer();
        server.route({ method: 'GET', path: '/nowhere', handler: { kibi_proxy: { host: 'no.such.domain.x8' } } });

        server.inject('/nowhere', (res) => {

            expect(res.statusCode).to.equal(502);
            done();
        });
    });

    it('errors on redirection to bad host (https)', (done) => {

        const server = provisionServer();
        server.route({ method: 'GET', path: '/nowhere', handler: { kibi_proxy: { host: 'no.such.domain.x8', protocol: 'https' } } });

        server.inject('/nowhere', (res) => {

            expect(res.statusCode).to.equal(502);
            done();
        });
    });

    it('redirects to another endpoint', (done) => {

        const redirectHandler = function (request, reply) {

            reply.redirect('/profile');
        };

        const profile = function (request, reply) {

            reply({ id: 'fa0dbda9b1b', name: 'John Doe' }).state('test', '123');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/redirect', handler: redirectHandler });
        upstream.route({ method: 'GET', path: '/profile', handler: profile, config: { cache: { expiresIn: 2000 } } });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/redirect', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, passThrough: true, redirects: 2 } } });
            server.state('auto', { autoValue: 'xyz' });

            server.inject('/redirect', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.contain('John Doe');
                expect(res.headers['set-cookie']).to.equal(['test=123', 'auto=xyz']);
                done();
            });
        });
    });

    it('redirects to another endpoint with relative location', (done) => {

        const redirectHandler = function (request, reply) {

            reply().header('Location', '//localhost:' + request.server.info.port + '/profile').code(302);
        };

        const profile = function (request, reply) {

            reply({ id: 'fa0dbda9b1b', name: 'John Doe' }).state('test', '123');
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/redirect', handler: redirectHandler });
        upstream.route({ method: 'GET', path: '/profile', handler: profile, config: { cache: { expiresIn: 2000 } } });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/redirect', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, passThrough: true, redirects: 2 } } });
            server.state('auto', { autoValue: 'xyz' });

            server.inject('/redirect?x=2', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.contain('John Doe');
                expect(res.headers['set-cookie']).to.equal(['test=123', 'auto=xyz']);
                done();
            });
        });
    });

    it('redirects to a post endpoint with stream', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'POST',
            path: '/post1',
            handler: function (request, reply) {

                return reply.redirect('/post2').rewritable(false);
            }
        });

        upstream.route({
            method: 'POST',
            path: '/post2',
            handler: function (request, reply) {

                return reply(request.payload);
            }
        });

        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'POST', path: '/post1', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, redirects: 3 } }, config: { payload: { output: 'stream' } } });

            server.inject({ method: 'POST', url: '/post1', payload: 'test', headers: { 'content-type': 'text/plain' } }, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.equal('test');
                done();
            });
        });
    });

    it('errors when proxied request times out', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/timeout1',
            handler: function (request, reply) {

                setTimeout(() => {

                    return reply('Ok');
                }, 10);
            }
        });

        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/timeout1', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, timeout: 5 } } });

            server.inject('/timeout1', (res) => {

                expect(res.statusCode).to.equal(504);
                done();
            });
        });
    });

    it('uses default timeout when nothing is set', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({

            method: 'GET',
            path: '/timeout2',
            handler: function (request, reply) {

                setTimeout(() => {

                    return reply('Ok');
                }, 10);
            }
        });

        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/timeout2', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port } } });

            server.inject('/timeout2', (res) => {

                expect(res.statusCode).to.equal(200);
                done();
            });
        });
    });

    it('uses rejectUnauthorized to allow proxy to self signed ssl server', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection({ tls: tlsOptions });
        upstream.route({
            method: 'GET',
            path: '/',
            handler: function (request, reply) {

                return reply('Ok');
            }
        });

        upstream.start(() => {

            const mapSslUri = function (request, callback) {

                return callback(null, 'https://127.0.0.1:' + upstream.info.port);
            };

            const server = provisionServer();
            server.route({ method: 'GET', path: '/allow', handler: { kibi_proxy: { mapUri: mapSslUri, rejectUnauthorized: false } } });
            server.inject('/allow', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.equal('Ok');
                done();
            });
        });
    });

    it('uses rejectUnauthorized to not allow proxy to self signed ssl server', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection({ tls: tlsOptions });
        upstream.route({
            method: 'GET',
            path: '/',
            handler: function (request, reply) {

                return reply('Ok');
            }
        });

        upstream.start(() => {

            const mapSslUri = function (request, callback) {

                return callback(null, 'https://127.0.0.1:' + upstream.info.port);
            };

            const server = provisionServer();
            server.route({ method: 'GET', path: '/reject', handler: { kibi_proxy: { mapUri: mapSslUri, rejectUnauthorized: true } } });
            server.inject('/reject', (res) => {

                expect(res.statusCode).to.equal(502);
                done();
            });
        });
    });

    it('the default rejectUnauthorized should not allow proxied server cert to be self signed', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection({ tls: tlsOptions });
        upstream.route({
            method: 'GET',
            path: '/',
            handler: function (request, reply) {

                return reply('Ok');
            }
        });

        upstream.start(() => {

            const mapSslUri = function (request, callback) {

                return callback(null, 'https://127.0.0.1:' + upstream.info.port);
            };

            const server = provisionServer();
            server.route({ method: 'GET', path: '/sslDefault', handler: { kibi_proxy: { mapUri: mapSslUri } } });
            server.inject('/sslDefault', (res) => {

                expect(res.statusCode).to.equal(502);
                done();
            });
        });
    });

    it('times out when proxy timeout is less than server', { parallel: false }, (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/timeout2',
            handler: function (request, reply) {

                setTimeout(() => {

                    return reply('Ok');
                }, 10);
            }
        });

        upstream.start(() => {

            const server = provisionServer({ routes: { timeout: { server: 8 } } });
            server.route({ method: 'GET', path: '/timeout2', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, timeout: 2 } } });
            server.inject('/timeout2', (res) => {

                expect(res.statusCode).to.equal(504);
                done();
            });
        });
    });

    it('times out when server timeout is less than proxy', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/timeout1',
            handler: function (request, reply) {

                setTimeout(() => {

                    return reply('Ok');
                }, 10);
            }
        });

        upstream.start(() => {

            const server = provisionServer({ routes: { timeout: { server: 5 } } });
            server.route({ method: 'GET', path: '/timeout1', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, timeout: 15 } } });
            server.inject('/timeout1', (res) => {

                expect(res.statusCode).to.equal(503);
                done();
            });
        });
    });

    it('proxies via uri template', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/item',
            handler: function (request, reply) {

                return reply({ a: 1 });
            }
        });

        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/handlerTemplate', handler: { kibi_proxy: { uri: '{protocol}://localhost:' + upstream.info.port + '/item' } } });

            server.inject('/handlerTemplate', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.contain('"a":1');
                done();
            });
        });
    });

    it('proxies via uri template with request.param variables', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/item/{param_a}/{param_b}',
            handler: function (request, reply) {

                return reply({ a: request.params.param_a, b:request.params.param_b });
            }
        });

        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/handlerTemplate/{a}/{b}', handler: { proxy: { uri: 'http://localhost:' + upstream.info.port + '/item/{a}/{b}' } } });

            const prma = 'foo';
            const prmb = 'bar';
            server.inject(`/handlerTemplate/${prma}/${prmb}`, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.contain(`"a":"${prma}"`);
                expect(res.payload).to.contain(`"b":"${prmb}"`);
                done();
            });
        });
    });

    it('passes upstream caching headers', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/cachedItem',
            handler: function (request, reply) {

                return reply({ a: 1 });
            },
            config: {
                cache: {
                    expiresIn: 2000
                }
            }
        });

        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/cachedItem', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, ttl: 'upstream' } } });
            server.state('auto', { autoValue: 'xyz' });

            server.inject('/cachedItem', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.headers['cache-control']).to.equal('max-age=2, must-revalidate, private');
                done();
            });
        });
    });

    it('ignores when no upstream caching headers to pass', (done) => {

        const upstream = Http.createServer((req, res) => {

            res.end('not much');
        });

        upstream.listen(0, () => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/', handler: { kibi_proxy: { host: 'localhost', port: upstream.address().port, ttl: 'upstream' } } });

            server.inject('/', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.headers['cache-control']).to.equal('no-cache');
                done();
            });
        });
    });

    it('ignores when upstream caching header is invalid', (done) => {

        const upstream = Http.createServer((req, res) => {

            res.writeHeader(200, { 'cache-control': 'some crap that does not work' });
            res.end('not much');
        });

        upstream.listen(0, () => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/', handler: { kibi_proxy: { host: 'localhost', port: upstream.address().port, ttl: 'upstream' } } });

            server.inject('/', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.headers['cache-control']).to.equal('no-cache');
                done();
            });
        });
    });

    it('overrides response code with 304', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/item',
            handler: function (request, reply) {

                return reply({ a: 1 });
            }
        });

        upstream.start(() => {

            const onResponse304 = function (err, res, request, reply, settings, ttl) {

                expect(err).to.be.null();
                return reply(res).code(304);
            };

            const server = provisionServer();
            server.route({ method: 'GET', path: '/304', handler: { kibi_proxy: { uri: 'http://localhost:' + upstream.info.port + '/item', onResponse: onResponse304 } } });

            server.inject('/304', (res) => {

                expect(res.statusCode).to.equal(304);
                expect(res.payload).to.equal('');
                done();
            });
        });
    });

    it('cleans up when proxy response replaced in onPreResponse', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/item',
            handler: function (request, reply) {

                return reply({ a: 1 });
            }
        });

        upstream.start(() => {

            const server = provisionServer();
            server.ext('onPreResponse', (request, reply) => {

                return reply({ something: 'else' });
            });

            server.route({ method: 'GET', path: '/item', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port } } });

            server.inject('/item', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.result.something).to.equal('else');
                done();
            });
        });
    });

    it('retails accept-encoding header', (done) => {

        const profile = function (request, reply) {

            reply(request.headers['accept-encoding']);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/', handler: profile, config: { cache: { expiresIn: 2000 } } });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, acceptEncoding: true, passThrough: true } } });

            server.inject({ url: '/', headers: { 'accept-encoding': '*/*' } }, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.equal('*/*');
                done();
            });
        });
    });

    it('removes accept-encoding header', (done) => {

        const profile = function (request, reply) {

            reply(request.headers['accept-encoding']);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/', handler: profile, config: { cache: { expiresIn: 2000 } } });
        upstream.start(() => {

            const server = provisionServer();
            server.route({ method: 'GET', path: '/', handler: { kibi_proxy: { host: 'localhost', port: upstream.info.port, acceptEncoding: false, passThrough: true } } });

            server.inject({ url: '/', headers: { 'accept-encoding': '*/*' } }, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.equal('');
                done();
            });
        });
    });

    it('does not send multiple Content-Type headers on passthrough', { parallel: false }, (done) => {

        const server = provisionServer();

        const requestFn = Wreck.request;
        Wreck.request = function (method, url, options, cb) {

            Wreck.request = requestFn;
            expect(options.headers['content-type']).to.equal('application/json');
            expect(options.headers['Content-Type']).to.not.exist();
            cb(new Error('placeholder'));
        };
        server.route({ method: 'GET', path: '/test', handler: { kibi_proxy: { uri: 'http://localhost', passThrough: true } } });
        server.inject({ method: 'GET', url: '/test', headers: { 'Content-Type': 'application/json' } }, (res) => {

            done();
        });
    });

    it('allows passing in an agent through to Wreck', { parallel: false }, (done) => {

        const server = provisionServer();
        const agent = { name: 'myagent' };

        const requestFn = Wreck.request;
        Wreck.request = function (method, url, options, cb) {

            Wreck.request = requestFn;
            expect(options.agent).to.equal(agent);
            done();

        };
        server.route({ method: 'GET', path: '/agenttest', handler: { kibi_proxy: { uri: 'http://localhost', agent } } });
        server.inject({ method: 'GET', url: '/agenttest', headers: {} }, (res) => { });
    });

    it('excludes request cookies defined locally', (done) => {

        const handler = function (request, reply) {

            reply(request.state);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/', handler });
        upstream.start(() => {

            const server = provisionServer();
            server.state('a');

            server.route({
                method: 'GET',
                path: '/',
                handler: {
                    kibi_proxy: {
                        host: 'localhost',
                        port: upstream.info.port,
                        passThrough: true
                    }
                }
            });

            server.inject({ url: '/', headers: { cookie: 'a=1;b=2' } }, (res) => {

                expect(res.statusCode).to.equal(200);
                const cookies = JSON.parse(res.payload);
                expect(cookies).to.equal({ b: '2' });
                done();
            });
        });
    });

    it('includes request cookies defined locally (route level)', (done) => {

        const handler = function (request, reply) {

            return reply(request.state);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/', handler });
        upstream.start(() => {

            const server = provisionServer();
            server.state('a', { passThrough: true });

            server.route({
                method: 'GET',
                path: '/',
                handler: {
                    kibi_proxy: {
                        host: 'localhost',
                        port: upstream.info.port,
                        passThrough: true,
                        localStatePassThrough: true
                    }
                }
            });

            server.inject({ url: '/', headers: { cookie: 'a=1;b=2' } }, (res) => {

                expect(res.statusCode).to.equal(200);
                const cookies = JSON.parse(res.payload);
                expect(cookies).to.equal({ a: '1', b: '2' });
                done();
            });
        });
    });

    it('includes request cookies defined locally (cookie level)', (done) => {

        const handler = function (request, reply) {

            reply(request.state);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/', handler });
        upstream.start(() => {

            const server = provisionServer();
            server.state('a', { passThrough: true });

            server.route({
                method: 'GET',
                path: '/',
                handler: {
                    kibi_proxy: {
                        host: 'localhost',
                        port: upstream.info.port,
                        passThrough: true
                    }
                }
            });

            server.inject({ url: '/', headers: { cookie: 'a=1;b=2' } }, (res) => {

                expect(res.statusCode).to.equal(200);
                const cookies = JSON.parse(res.payload);
                expect(cookies).to.equal({ a: '1', b: '2' });
                done();
            });
        });
    });

    it('errors on invalid cookie header', (done) => {

        const server = provisionServer({ routes: { state: { failAction: 'ignore' } } });
        server.state('a', { passThrough: true });

        server.route({
            method: 'GET',
            path: '/',
            handler: {
                kibi_proxy: {
                    host: 'localhost',
                    port: 8080,
                    passThrough: true
                }
            }
        });

        server.inject({ url: '/', headers: { cookie: 'a' } }, (res) => {

            expect(res.statusCode).to.equal(400);
            done();
        });
    });

    it('drops cookies when all defined locally', (done) => {

        const handler = function (request, reply) {

            reply(request.state);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/', handler });
        upstream.start(() => {

            const server = provisionServer();
            server.state('a');

            server.route({
                method: 'GET',
                path: '/',
                handler: {
                    kibi_proxy: {
                        host: 'localhost',
                        port: upstream.info.port,
                        passThrough: true
                    }
                }
            });

            server.inject({ url: '/', headers: { cookie: 'a=1' } }, (res) => {

                expect(res.statusCode).to.equal(200);
                const cookies = JSON.parse(res.payload);
                expect(cookies).to.equal({});
                done();
            });
        });
    });

    it('excludes request cookies defined locally (state override)', (done) => {

        const handler = function (request, reply) {

            return reply(request.state);
        };

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({ method: 'GET', path: '/', handler });
        upstream.start(() => {

            const server = provisionServer();
            server.state('a', { passThrough: false });

            server.route({
                method: 'GET',
                path: '/',
                handler: {
                    kibi_proxy: {
                        host: 'localhost',
                        port: upstream.info.port,
                        passThrough: true
                    }
                }
            });

            server.inject({ url: '/', headers: { cookie: 'a=1;b=2' } }, (res) => {

                expect(res.statusCode).to.equal(200);
                const cookies = JSON.parse(res.payload);
                expect(cookies).to.equal({ b: '2' });
                done();
            });
        });
    });

    it('uses reply decorator', (done) => {

        const upstream = new Hapi.Server();
        upstream.connection();
        upstream.route({
            method: 'GET',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            }
        });
        upstream.start(() => {

            const server = provisionServer();
            server.route({
                method: 'GET',
                path: '/',
                handler: function (request, reply) {

                    return reply.kibi_proxy({ host: 'localhost', port: upstream.info.port, xforward: true, passThrough: true });
                }
            });

            server.inject('/', (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.payload).to.equal('ok');
                done();
            });
        });
    });
});
