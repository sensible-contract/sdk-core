export type API_NET = "mainnet" | "testnet";

export type InputInfo = {
  inputIndex: number;
  scriptHex: string;
  satoshis: number;
  sighashType?: number;
  address?: number | string;
};

export type SigResult = {
  sig: string;
  publicKey: string;
};

export const PLACE_HOLDER_SIG =
  "41682c2074686973206973206120706c61636520686f6c64657220616e642077696c6c206265207265706c6163656420696e207468652066696e616c207369676e61747572652e00";
export const PLACE_HOLDER_PUBKEY =
  "41682c2074686973206973206120706c61636520686f6c64657220616e64207769";
export const P2PKH_UNLOCK_SIZE = 1 + 1 + 72 + 1 + 33;

export const RABIN_SIG_LEN = 384;
