import { BN } from "@sensible-contract/bsv";
import { Bytes, Int, toHex } from "scryptlib";
import { RABIN_SIG_LEN } from "../constants";
import { CodeError, ErrCode } from "./error";
import { SatotxSigner, SignerConfig } from "./SatotxSigner";
import * as Utils from "./utils";

export async function getRabinDataEmpty(
  signers: SatotxSigner[],
  signerSelecteds: number[]
) {
  let rabinMsg: Bytes;
  let rabinPaddingArray: Bytes[] = [];
  let rabinSigArray: Int[] = [];
  rabinMsg = new Bytes("");
  signerSelecteds.forEach((v) => {
    rabinPaddingArray.push(new Bytes(""));
    rabinSigArray.push(new Int(0));
  });
  let rabinPubKeyIndexArray: number[] = signerSelecteds;
  let rabinPubKeyVerifyArray: Int[] = [];
  rabinPubKeyIndexArray.forEach((signerIndex) => {
    rabinPubKeyVerifyArray.push(
      new Int(signers[signerIndex].satotxPubKey.toString(10))
    );
  });
  return {
    rabinData: {
      rabinMsg,
      rabinPaddingArray,
      rabinSigArray,
    },
    rabinPubKeyIndexArray,
    rabinPubKeyVerifyArray,
  };
}
export async function getRabinData(
  signers: SatotxSigner[],
  signerSelecteds: number[],
  rabinUtxo?: {
    preTxId?: string;
    preOutputIndex?: number;
    preTxHex?: string;
    txId?: string;
    txHex?: string;
  }
) {
  let rabinMsg: Bytes;
  let rabinPaddingArray: Bytes[] = [];
  let rabinSigArray: Int[] = [];

  let rabinPubKeyIndexArray: number[] = signerSelecteds;
  let rabinPubKeyVerifyArray: Int[] = [];
  if (!rabinUtxo) {
    rabinMsg = new Bytes("");
    for (let i = 0; i < rabinPubKeyIndexArray.length; i++) {
      rabinPaddingArray.push(new Bytes(""));
      rabinSigArray.push(new Int(0));
    }
  } else {
    let sigReqArray = [];
    rabinPubKeyIndexArray.forEach((signerIndex) => {
      sigReqArray.push(
        signers[signerIndex].satotxApi.satoTxSigUTXOSpendBy({
          txId: rabinUtxo.preTxId,
          index: rabinUtxo.preOutputIndex,
          txHex: rabinUtxo.preTxHex,
          byTxId: rabinUtxo.txId,
          byTxHex: rabinUtxo.txHex,
        })
      );
    });
    for (let j = 0; j < sigReqArray.length; j++) {
      let sigInfo = await sigReqArray[j];
      if (j == 0) {
        rabinMsg = new Bytes(sigInfo.payload);
      }
      rabinSigArray.push(
        new Int(BN.fromString(sigInfo.sigBE, 16).toString(10))
      );
      rabinPaddingArray.push(new Bytes(sigInfo.padding));
    }
  }

  rabinPubKeyIndexArray.forEach((signerIndex) => {
    rabinPubKeyVerifyArray.push(
      new Int(signers[signerIndex].satotxPubKey.toString(10))
    );
  });

  return {
    rabinData: {
      rabinMsg,
      rabinPaddingArray,
      rabinSigArray,
    },
    rabinPubKeyIndexArray,
    rabinPubKeyVerifyArray,
  };
}

export async function getRabinDatas(
  signers: SatotxSigner[],
  signerSelecteds: number[],
  rabinInputs?: {
    preTxId?: string;
    preOutputIndex?: number;
    preTxHex?: string;
    txId?: string;
    outputIndex?: number;
    txHex?: string;
  }[]
) {
  let rabinDatas: {
    rabinMsg: Bytes;
    rabinPaddingArray: Bytes[];
    rabinSigArray: Int[];
  }[] = [];

  let checkRabinData: {
    rabinMsg: Bytes;
    rabinPaddingArray: Bytes[];
    rabinSigArray: Int[];
  } = {
    rabinMsg: new Bytes(""),
    rabinPaddingArray: [],
    rabinSigArray: [],
  };
  let checkRabinMsgArray = Buffer.alloc(0);
  let checkRabinPaddingArray = Buffer.alloc(0);
  let checkRabinSigArray = Buffer.alloc(0);

  let rabinPubKeyIndexArray: number[] = signerSelecteds;
  let rabinPubKeyVerifyArray: Int[] = [];

  let sigReqArray = [];
  for (let i = 0; i < rabinInputs.length; i++) {
    let v = rabinInputs[i];
    sigReqArray[i] = [];
    rabinPubKeyIndexArray.forEach((signerIndex) => {
      sigReqArray[i].push(
        signers[signerIndex].satotxApi.satoTxSigUTXOSpendByUTXO({
          txId: v.preTxId,
          index: v.preOutputIndex,
          txHex: v.preTxHex,
          byTxIndex: v.outputIndex,
          byTxId: v.txId,
          byTxHex: v.txHex,
        })
      );
    });
  }
  //Rabin Signature informations provided to TransferCheck/UnlockCheck
  for (let i = 0; i < sigReqArray.length; i++) {
    for (let j = 0; j < sigReqArray[i].length; j++) {
      let sigInfo = await sigReqArray[i][j];
      if (j == 0) {
        checkRabinMsgArray = Buffer.concat([
          checkRabinMsgArray,
          Buffer.from(sigInfo.byTxPayload, "hex"),
        ]);
        checkRabinData.rabinMsg = new Bytes(sigInfo.byTxPayload);
      }

      const sigBuf = Utils.toBufferLE(sigInfo.byTxSigBE, RABIN_SIG_LEN);
      checkRabinSigArray = Buffer.concat([checkRabinSigArray, sigBuf]);
      const paddingCountBuf = Buffer.alloc(2, 0);
      paddingCountBuf.writeUInt16LE(sigInfo.byTxPadding.length / 2);
      const padding = Buffer.alloc(sigInfo.byTxPadding.length / 2, 0);
      padding.write(sigInfo.byTxPadding, "hex");
      checkRabinPaddingArray = Buffer.concat([
        checkRabinPaddingArray,
        paddingCountBuf,
        padding,
      ]);
      checkRabinData.rabinSigArray.push(
        new Int(BN.fromString(sigInfo.byTxSigBE, 16).toString(10))
      );
      checkRabinData.rabinPaddingArray.push(new Bytes(sigInfo.byTxPadding));
    }
  }
  //Rabin Signature informations provided to Token

  for (let i = 0; i < sigReqArray.length; i++) {
    let rabinMsg: Bytes;
    let rabinSigArray: Int[] = [];
    let rabinPaddingArray: Bytes[] = [];
    for (let j = 0; j < sigReqArray[i].length; j++) {
      let sigInfo = await sigReqArray[i][j];
      rabinMsg = new Bytes(sigInfo.payload);
      rabinSigArray.push(
        new Int(BN.fromString(sigInfo.sigBE, 16).toString(10))
      );
      rabinPaddingArray.push(new Bytes(sigInfo.padding));
    }
    rabinDatas.push({
      rabinMsg,
      rabinSigArray,
      rabinPaddingArray,
    });
  }

  rabinPubKeyIndexArray.forEach((signerIndex) => {
    rabinPubKeyVerifyArray.push(
      new Int(signers[signerIndex].satotxPubKey.toString(10))
    );
  });
  return {
    rabinDatas,
    checkRabinDatas: {
      rabinMsgArray: new Bytes(toHex(checkRabinMsgArray)),
      rabinPaddingArray: new Bytes(toHex(checkRabinPaddingArray)),
      rabinSigArray: new Bytes(toHex(checkRabinSigArray)),
    },
    checkRabinData,
    rabinPubKeyIndexArray,
    rabinPubKeyVerifyArray,
  };
}

export async function selectSigners(
  signerConfigs: SignerConfig[],
  signerNum: number,
  signerVerifyNum: number
) {
  let _signerConfigs = signerConfigs.map((v) => Object.assign({}, v));
  if (_signerConfigs.length < signerNum) {
    throw new CodeError(
      ErrCode.EC_INVALID_ARGUMENT,
      `The length of signerArray should be ${signerNum}`
    );
  }
  let retPromises = [];
  const SIGNER_TIMEOUT = 99999;
  for (let i = 0; i < _signerConfigs.length; i++) {
    let signerConfig = _signerConfigs[i];
    let subArray = signerConfig.satotxApiPrefix.split(",");
    let ret = new Promise(
      (
        resolve: ({
          url,
          pubKey,
          duration,
          idx,
        }: {
          url: string;
          pubKey: string;
          duration: number;
          idx: number;
        }) => void,
        reject
      ) => {
        let hasResolve = false;
        let failedCnt = 0;
        for (let j = 0; j < subArray.length; j++) {
          let url = subArray[j];
          let signer = new SatotxSigner(url);
          let d1 = Date.now();
          signer.satotxApi
            .getInfo()
            .then(({ pubKey }) => {
              let duration = Date.now() - d1;
              if (!hasResolve) {
                hasResolve = true;
                resolve({ url, pubKey, duration, idx: i });
              }
            })
            .catch((e) => {
              failedCnt++;
              if (failedCnt == subArray.length) {
                resolve({
                  url,
                  pubKey: null,
                  duration: SIGNER_TIMEOUT,
                  idx: i,
                });
                // reject(`failed to get info by ${url}`);
              }
              //ignore
            });
        }
      }
    );
    retPromises.push(ret);
  }

  let results = [];
  for (let i = 0; i < _signerConfigs.length; i++) {
    let signerConfig = _signerConfigs[i];
    let ret = await retPromises[i];
    signerConfig.satotxApiPrefix = ret.url;
    results.push(ret);
  }
  let signerSelecteds: number[] = results
    .filter((v) => v.duration < SIGNER_TIMEOUT)
    .sort((a, b) => a.duration - b.duration)
    .slice(0, signerVerifyNum)
    .map((v) => v.idx);
  if (signerSelecteds.length < signerVerifyNum) {
    throw new CodeError(
      ErrCode.EC_INNER_ERROR,
      `Less than ${signerVerifyNum} successful signer requests`
    );
  }
  return {
    signers: _signerConfigs,
    signerSelecteds,
  };
}
