import { Sender as RawSender } from './simple_secrets';
import msgpack from 'msgpack'

export class Sender {
  constructor(key) {
    this._sender = new RawSender(key);
  }

  pack(value) {
    return this._sender.pack(msgpack.pack(value));
  }

  unpack(value) {
    var payload = this._sender.unpack(value);
    return msgpack.unpack(payload);
  }
};
