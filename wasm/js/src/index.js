import { Sender as RawSender } from './simple_secrets';
import msgpack from 'msgpack'

export class Sender {
  free() {
    this._sender.free();
  }

  constructor(key) {
    try {
      this._sender = new RawSender(key);
    } catch (msg) {
      throw new Error(msg);
    }
  }

  pack(value) {
    return this.packRaw(msgpack.pack(value));
  }

  packRaw(value) {
    try {
      return this._sender.pack(value);
    } catch (msg) {
      throw new Error(msg);
    }
  }

  unpack(value) {
    return msgpack.unpack(this.unpackRaw(value));
  }

  unpackRaw(value) {
    try {
      return this._sender.unpack(value);
    } catch (msg) {
      throw new Error(msg);
    }
  }
};
