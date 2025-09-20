export interface ApiMessage {
  msg: string
}

export interface ApiResponse<T = any> {
  data?: T
  error?: string
}