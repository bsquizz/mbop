let chai = require('chai');
let chaiHttp = require('chai-http');
let chaiJSON = require('chai-json');
var expect = chai.expect;
let should = chai.should();
var assert = chai.assert;


chai.use(chaiHttp);
chai.use(chaiJSON);

const url= 'http://localhost:8090';


/*
 * Test / route
 */
describe('/GET /',() => {
    it('should return 200', (done) => {
        chai.request(url)
            .get('/')
            .end((err,res) => {
                res.should.have.status(200);
            done();
        });
    });
});


/*
 * Test /v1/users
 */

describe('/GET /v1/users',() => {
    it('should return 405', (done) => {
        chai.request(url)
            .get('/v1/users')
            .end((err,res) => {
                res.should.have.status(405);
            done();
        });
    });
});


describe('/POST /v1/users',() => {
    it("should handle if body includes malformed input", (done) => {
        chai.request(url)
            .post('/v1/users')
            .send("foo")
            .end((err,res) => {
                res.should.have.status(500);
                expect(res.text).to.contain("malformed input");
            done();
        });
    });
});



describe('/POST /v1/users',() => {
    it("should find users if sent username", (done) => {
        chai.request(url)
            .post('/v1/users')
            .send({"users": ["jdoe"]})
            .end((err,res) => {
                res.should.have.status(200);
                JSON_response = JSON.parse(res.text);
                expect(JSON_response.length).eq(1);
                expect(JSON_response[0].username).eq("jdoe");
            done();
        });
    });
});


describe('/POST /v1/users',() => {
    it("should filter out users if sent non existing username", (done) => {
        chai.request(url)
            .post('/v1/users')
            .send({"users": ["foobar"]})
            .end((err,res) => {
                res.should.have.status(200);
                JSON_response = JSON.parse(res.text);
                expect(JSON_response).be.empty;
            done();
        });
    });
});



describe('/POST /v1/users',() => {
    it.skip("should find users even without any parameter", (done) => {
        chai.request(url)
            .post('/v1/users')
            .end((err,res) => {
                res.should.have.status(200);
                JSON_response = JSON.parse(res.text);
                expect(JSON_response).not.be.empty;
            done();
        });
    });
});

/*
 * Test /v1/jwt
 */
describe('/POST /v1/jwt',() => {
    it.skip("should get the jwt auth token", (done) => {
        chai.request(url)
            .post('/v1/jwt')
            .end((err,res) => {
                res.should.have.status(200);
                JSON_response = JSON.parse(res.text);
                expect(JSON_response).not.be.empty;
            done();
        });
    });
});

/*
 * Test /v1/auth
 */

/*
 * Test /v1/accounts
 */
describe('/GET /v1/accounts',() => {
    it('should return the users sorted by desc', (done) => {
        chai.request(url)
            .get('/v1/accounts/12345/users')
            .end((err,res) => {
                res.should.have.status(200);
            done();
        });
    });
});

/*
 * Test /v2/accounts
 */
describe('/GET /v2/accounts',() => {
    it('should return the users sorted by desc', (done) => {
        chai.request(url)
            .get('/v2/accounts/12345/users')
            .end((err,res) => {
                res.should.have.status(200);
            done();
        });
    });
});

/*
 * Test /v3/accounts
 */
describe('/GET /v3/accounts',() => {
    it('should return the users sorted by desc', (done) => {
        chai.request(url)
            .get('/v3/accounts/12345/users')
            .end((err,res) => {
                res.should.have.status(200);
            done();
        });
    });
});

/*
 * Test /api/entitlements/v1/services
 */
