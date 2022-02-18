interface GetOrSetNonceParams {
  pub_key_X: string
  pub_key_Y: string
  set_data: {
    data: 'getNonce' | 'getOrSetNonce' | string
    timestamp: string
  }
  signature: string
}

export interface MetaDataResponse {
  message: string
}

export interface MetaDataParams {
  pub_key_X: string
  pub_key_Y: string
  set_data: {
    data: 'getNonce' | 'getOrSetNonce' | string
    timestamp: string
  }
  signature: string
}
