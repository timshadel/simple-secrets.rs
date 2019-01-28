import { Sender as RawSender } from './simple_secrets';
import msgpack from 'msgpack'

export class Sender {
  free() {
    this._sender.free();
  }

  constructor(key) {
    this._sender = new RawSender(key);
  }

  pack(value) {
    return this.packRaw(msgpack.pack(value));
  }

  packRaw(value) {
    return this._sender.pack(value);
  }

  unpack(value) {
    return msgpack.unpack(this.unpackRaw(value));
  }

  unpackRaw(value) {
    return this._sender.unpack(value);
  }
};
