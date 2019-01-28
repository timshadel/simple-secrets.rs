const { Sender } = require('../');
const msgpack = require('msgpack');
require('jasmine-check').install();

const sender = new Sender('eda00b0f46f6518d4c77944480a0b9b0a7314ad45e124521e490263c2ea217ad');

describe('SimpleSecrets', () => {
  check.it('round trip', gen.any, (value) => {
    expect(
      sender.unpack(sender.pack(value))
    ).toEqual(
      msgpack.unpack(msgpack.pack(value))
    );
  });
});
