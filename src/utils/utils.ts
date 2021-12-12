import * as bsv from "@sensible-contract/bsv";
import { toHex } from "scryptlib";
import {
  InputInfo,
  PLACE_HOLDER_PUBKEY,
  PLACE_HOLDER_SIG,
  RABIN_SIG_LEN,
  SigResult,
} from "../constants";
import { BN } from "@sensible-contract/bsv";

export let toBufferLE = function (num: number | string, width: number) {
  const hex = num.toString(16);
  const buffer = Buffer.from(
    hex.padStart(width * 2, "0").slice(0, width * 2),
    "hex"
  );
  buffer.reverse();
  return buffer;
};

export let getUInt8Buf = function (amount: number) {
  const buf = Buffer.alloc(1, 0);
  buf.writeUInt8(amount);
  return buf;
};

export let getUInt16Buf = function (amount: number) {
  const buf = Buffer.alloc(2, 0);
  buf.writeUInt16LE(amount);
  return buf;
};

export let getUInt32Buf = function (index: number) {
  const buf = Buffer.alloc(4, 0);
  buf.writeUInt32LE(index);
  return buf;
};

export let getUInt64Buf = function (amount: number) {
  return new BN(amount.toString()).toBuffer({ endian: "little", size: 8 });
};

export let getTxIdBuf = function (txid: string) {
  const buf = Buffer.from(txid, "hex").reverse();
  return buf;
};

export let getScriptHashBuf = function (scriptBuf: Buffer) {
  const buf = Buffer.from(bsv.crypto.Hash.sha256ripemd160(scriptBuf));
  return buf;
};

export let writeVarint = function (buf: Buffer) {
  const n = buf.length;
  let header: Buffer;
  let res = Buffer.alloc(0);
  if (n < 0xfd) {
    header = getUInt8Buf(n);
  } else if (n < 0x10000) {
    header = Buffer.concat([Buffer.from("fd", "hex"), getUInt16Buf(n)]);
  } else if (n < 0x100000000) {
    header = Buffer.concat([Buffer.from("fe", "hex"), getUInt32Buf(n)]);
  } else if (n < 0x10000000000000000) {
    header = Buffer.concat([Buffer.from("ff", "hex"), getUInt64Buf(n)]);
  }

  return Buffer.concat([header, buf]);
};

export let getLockingScriptFromPreimage = function (buf: Buffer) {
  const offset = 4 + 32 + 32 + 32 + 4;
  buf = buf.slice(offset, buf.length);
  const n = buf[0];
  buf = buf.slice(1, buf.length);
  let lockingScriptBuf;
  if (n < 0xfd) {
    let len = buf.slice(0, 1).readInt8(0);
    lockingScriptBuf = buf.slice(1, len + 1);
  } else if (n < 0x10000) {
    let len = buf.slice(0, 2).readInt16LE(0);
    lockingScriptBuf = buf.slice(2, len + 2);
  } else if (n < 0x100000000) {
    let len = buf.slice(0, 3).readInt32LE(0);
    lockingScriptBuf = buf.slice(3, len + 3);
  } else if (n < 0x10000000000000000) {
    let len = buf.slice(0, 4).readInt32LE(0);
    lockingScriptBuf = buf.slice(4, len + 4);
  }
  return lockingScriptBuf;
};

export let getGenesisHashFromLockingScript = function (
  lockingScript: any
): Buffer {
  let genesisHash: Buffer;
  let c = 0;
  for (let i = 0; i < lockingScript.chunks.length; i++) {
    let chunk = lockingScript.chunks[i];
    if (chunk.buf && chunk.buf.length == 20) {
      c++;
      if (c == 11) {
        genesisHash = chunk.buf;
        break;
      }
    }
  }
  return genesisHash;
};

export let getRabinPubKeyHashArray = function (rabinPubKeys: BN[]) {
  let buf = Buffer.alloc(0);
  for (let i = 0; i < rabinPubKeys.length; i++) {
    buf = Buffer.concat([
      buf,
      bsv.crypto.Hash.sha256ripemd160(
        toBufferLE(rabinPubKeys[i].toString(16), RABIN_SIG_LEN)
      ),
    ]);
  }
  return buf;
};

export function getOutpointBuf(txid: string, index: number): Buffer {
  const txidBuf = Buffer.from(txid, "hex").reverse();
  const indexBuf = Buffer.alloc(4, 0);
  indexBuf.writeUInt32LE(index);
  let buf = Buffer.concat([txidBuf, indexBuf]);
  return buf;
}

export function getDustThreshold(lockingScriptSize: number) {
  return 3 * Math.ceil((250 * (lockingScriptSize + 9 + 148)) / 1000);
}

export function isNull(val: any) {
  if (typeof val == "undefined" || val == null || val == "undefined") {
    return true;
  } else {
    return false;
  }
}

export function getVarPushdataHeader(n: number): Buffer {
  let header = "";
  if (n == 0) {
  } else if (n == 1) {
    //不处理这种情况，这里只考虑长脚本
  } else if (n < 76) {
    // Use direct push
    header = toHex(getUInt8Buf(n));
  } else if (n <= 255) {
    header = "4c" + toHex(getUInt8Buf(n));
  } else if (n <= 65535) {
    header = "4d" + toHex(getUInt16Buf(n));
  } else {
    header = "4e" + toHex(getUInt32Buf(n));
  }
  return Buffer.from(header, "hex");
}

export function numberToBuffer(n: number) {
  let str = n.toString(16);
  if (str.length % 2 == 1) {
    str = "0" + str;
  }
  return Buffer.from(str, "hex");
}

export function sign(
  tx: bsv.Transaction,
  inputInfos: InputInfo[],
  sigResults: SigResult[]
) {
  inputInfos.forEach(({ inputIndex, sighashType, scriptHex }, index) => {
    let input = tx.inputs[inputIndex];
    let sigInfo = sigResults[index];
    let publicKey = new bsv.PublicKey(sigInfo.publicKey);
    let _sig = bsv.crypto.Signature.fromString(sigInfo.sig);
    _sig.nhashtype = sighashType;
    if (input.script.toHex()) {
      let _sig2 = _sig.toTxFormat();
      let oldSigHex = Buffer.concat([
        numberToBuffer(PLACE_HOLDER_SIG.length / 2),
        Buffer.from(PLACE_HOLDER_SIG, "hex"),
      ]).toString("hex");

      let newSigHex = Buffer.concat([
        numberToBuffer(_sig2.length),
        _sig2,
      ]).toString("hex");

      let oldPubKeyHex = Buffer.concat([
        numberToBuffer(PLACE_HOLDER_PUBKEY.length / 2),
        Buffer.from(PLACE_HOLDER_PUBKEY, "hex"),
      ]).toString("hex");

      const pubkeyBuffer = publicKey.toBuffer();
      let newPubKeyHex = Buffer.concat([
        numberToBuffer(pubkeyBuffer.length),
        pubkeyBuffer,
      ]).toString("hex");

      input.setScript(
        new bsv.Script(
          input.script
            .toHex()
            .replace(oldSigHex, newSigHex)
            .replace(oldPubKeyHex, newPubKeyHex)
        )
      );
    } else {
      const signature = new bsv.Transaction.Signature({
        publicKey,
        prevTxId: input.prevTxId,
        outputIndex: input.outputIndex,
        inputIndex: inputIndex,
        signature: _sig,
        sigtype: sighashType,
      });
      input.setScript(
        bsv.Script.buildPublicKeyHashIn(
          signature.publicKey,
          signature.signature.toDER(),
          signature.sigtype
        )
      );
    }
  });
}

function satoshisToBSV(satoshis) {
  return (satoshis / 100000000).toFixed(8);
}
export function dumpTx(tx: bsv.Transaction, network = "mainnet") {
  const version = tx.version;
  const size = tx.toBuffer().length;
  const inputAmount = tx.inputs.reduce(
    (pre, cur) => cur.output.satoshis + pre,
    0
  );
  const outputAmount = tx.outputs.reduce((pre, cur) => cur.satoshis + pre, 0);
  let feePaid = inputAmount - outputAmount;

  const feeRate = (feePaid / size).toFixed(4);

  console.log(`
=============================================================================================
Summary
  txid:     ${tx.id}
  Size:     ${size}
  Fee Paid: ${satoshisToBSV(feePaid)}
  Fee Rate: ${feeRate} sat/B
  Detail:   ${tx.inputs.length} Inputs, ${tx.outputs.length} Outputs
----------------------------------------------------------------------------------------------
${tx.inputs
  .map((input, index) => {
    let type = "";
    if (input.output.script.isPublicKeyHashOut()) {
      type = "standard";
    } else if (input.output.script.isSafeDataOut()) {
      type = "OP_RETURN";
    } else {
      type = "nonstandard";
    }
    let str = `
=>${index}    ${
      type == "standard"
        ? input.output.script.toAddress(network).toString()
        : type == "OP_RETURN"
        ? "OP_RETURN" + " ".repeat(34 - 9)
        : "nonstandard" + " ".repeat(34 - 11)
    }    ${satoshisToBSV(input.output.satoshis)} BSV
       lock-size:   ${input.output.script.toBuffer().length}
       unlock-size: ${input.script.toBuffer().length}
       via ${input.prevTxId.toString("hex")} [${input.outputIndex}]
`;
    return str;
  })
  .join("")}
Input total: ${satoshisToBSV(
    tx.inputs.reduce((pre, cur) => pre + cur.output.satoshis, 0)
  )} BSV
----------------------------------------------------------------------------------------------
${tx.outputs
  .map((output, index) => {
    let type = "";
    if (output.script.isPublicKeyHashOut()) {
      type = "standard";
    } else if (output.script.isSafeDataOut()) {
      type = "OP_RETURN";
    } else {
      type = "nonstandard";
    }
    let str = `
=>${index}    ${
      type == "standard"
        ? output.script.toAddress(network).toString()
        : type == "OP_RETURN"
        ? "OP_RETURN" + " ".repeat(34 - 9)
        : "nonstandard" + " ".repeat(34 - 11)
    }    ${satoshisToBSV(output.satoshis)} BSV
       size: ${output.script.toBuffer().length}
		`;
    return str;
  })
  .join("")}
Output total: ${satoshisToBSV(
    tx.outputs.reduce((pre, cur) => pre + cur.satoshis, 0)
  )} BSV
=============================================================================================
	 `);
}
