import { BN } from "@sensible-contract/bsv";
import { SatotxApi } from "@sensible-contract/satotx-api";

export type SignerConfig = {
  satotxApiPrefix: string;
  satotxPubKey: string;
};

function fixApiPrefix(api: string) {
  api = api.split(",")[0];
  if (api[api.length - 1] == "/") {
    api = api.slice(0, api.length - 1);
  }
  return api;
}

export class SatotxSigner {
  satotxApi?: SatotxApi;
  satotxPubKey?: BN;
  constructor(satotxApiPrefix?: string, satotxPubKey?: string) {
    if (satotxApiPrefix) {
      satotxApiPrefix = fixApiPrefix(satotxApiPrefix);
    }
    this.satotxApi = new SatotxApi(satotxApiPrefix);
    if (satotxPubKey) {
      this.satotxPubKey = BN.fromString(satotxPubKey, 16);
    }
  }
}
