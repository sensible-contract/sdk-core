import * as bsv from "@sensible-contract/bsv";
import { BN } from "@sensible-contract/bsv";
import { RABIN_SIG_LEN } from "../constants";
import * as Utils from "./utils";
const SIGNER_NUM = 5;
const network = "mainnet";
export const dummyTxId =
  "c776133a77886693ba2484fe12d6bdfb8f8bcb7a237e4a8a6d0f69c7d1879a08";
export const dummyPrivateKey = bsv.PrivateKey.fromWIF(
  "L5k7xi4diSR8aWoGKojSNTnc3YMEXEoNpJEaGzqWimdKry6CFrzz"
);
export const dummyAddress = dummyPrivateKey.toAddress(network);
export const dummyPk = dummyPrivateKey.toPublicKey();
export const dummyCodehash = dummyPk;
export const dummyTx = new bsv.Transaction(
  "010000000146a476c09fa48d0db861dc5c9e28dc11f9262a89d057a03d8896e93458b82e0f010000006a47304402200b70b1feb364ffe0245c78a2d163fca4bfd808976acbbb3579ba71807bd9b307022074bf5058166902632987e68a3fc6e0d6e36def18c7c184acd50dfedfa72830d9412103ac3f50a7670cd94792a61992d98aeaba4681de7777997f23fdc1ff32438f267efeffffff02e8030000000000001976a9145008595623e5364f71fea7a4ddfc20c069a028a088ace4f00c00000000001976a914200fcbd6341db16487f566b4718879409c31ed0088ac3b960a00"
);
export const dummySigBE =
  "081ee271502451358f3ef61cea2c223980c4a45fd79073b2744e167ebd93bfaaf98458eca107126d2a8d1f450ba8f293f9a1031a68e686c43d369b6cebacb498d921b0cb60a4747a0a9a75d2bbd233e90cab3569029e9ba54a129521a8935d68539916fc4ff756a7a072a59f7698169301a92babe9c013c3db1e2c3ca2f603ac57218c1bb638dd4d7b4ed7816635dea15992e184db47b3266326d4b88dd352eb3bc2e944e630288a5add3734877dfa23e7755c19205c04bed91f5482e26e58a1629a33e55b2826454d36a030ca82119d257e10761974d64247e2c58ed2ec333cd03721cbb2784955077c2a53bc8f9500d2b6fdce061f8e3fb6287ec1b36705ee719c8905fbd32578db7a719f904a264a578c00ddb51425ff220f2ca4f01e744b37cc4712930f7cc82cd149bb3f00a98d6c98a0512a2a189c7adde27bb5374155b44a3b66493f7bde9a2c0e1e80a260b46f6e2d1d3f88669b422d4b8793b17286fd97b367e671d026f3d2e383b1e412fa830ddfbe2dcae6054ed8527064959263";
export const dummyPayload =
  "43c5967c870e31cc5fe07c626aa0cf52569d23d344afca15cc5156d88c1bb8dc0100000064ac9c0000000000af4a1ee6224ae65681fb0adb2e00b979c9926c1392848643ff517ac66c8ffd04a4028ac8eebc45951549c5867a338cf446372f1d";
export const dummyPadding = "0200";
export const dummyRabinPubKey = BN.fromString(
  "2c8c0117aa5edba9a4539e783b6a1bdbc1ad88ad5b57f3d9c5cba55001c45e1fedb877ebc7d49d1cfa8aa938ccb303c3a37732eb0296fee4a6642b0ff1976817b603404f64c41ec098f8cd908caf64b4a3aada220ff61e252ef6d775079b69451367eda8fdb37bc55c8bfd69610e1f31b9d421ff44e3a0cfa7b11f334374827256a0b91ce80c45ffb798798e7bd6b110134e1a3c3fa89855a19829aab3922f55da92000495737e99e0094e6c4dbcc4e8d8de5459355c21ff055d039a202076e4ca263b745a885ef292eec0b5a5255e6ecc45534897d9572c3ebe97d36626c7b1e775159e00b17d03bc6d127260e13a252afd89bab72e8daf893075f18c1840cb394f18a9817913a9462c6ffc8951bee50a05f38da4c9090a4d6868cb8c955e5efb4f3be4e7cf0be1c399d78a6f6dd26a0af8492dca67843c6da9915bae571aa9f4696418ab1520dd50dd05f5c0c7a51d2843bd4d9b6b3b79910e98f3d98099fd86d71b2fac290e32bdacb31943a8384a7668c32a66be127b74390b4b0dec6455",
  16
);

let buf = Buffer.alloc(0);
for (let i = 0; i < SIGNER_NUM; i++) {
  buf = Buffer.concat([
    buf,
    bsv.crypto.Hash.sha256ripemd160(
      Utils.toBufferLE(dummyRabinPubKey.toString("hex"), RABIN_SIG_LEN)
    ),
  ]);
}
export const dummyRabinPubKeyHashArray = buf;

export function getZeroAddress(network: "mainnet" | "testnet") {
  if (network == "mainnet") {
    return new bsv.Address("1111111111111111111114oLvT2");
  } else {
    return new bsv.Address("mfWxJ45yp2SFn7UciZyNpvDKrzbhyfKrY8");
  }
}
