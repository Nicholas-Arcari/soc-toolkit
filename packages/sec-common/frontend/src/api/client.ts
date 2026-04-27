import axios, { AxiosInstance, AxiosRequestConfig } from "axios";

export interface CreateApiClientOptions {
  baseURL: string;
  headers?: Record<string, string>;
  config?: AxiosRequestConfig;
}

export function createApiClient({
  baseURL,
  headers,
  config,
}: CreateApiClientOptions): AxiosInstance {
  return axios.create({
    baseURL,
    headers: {
      "Content-Type": "application/json",
      ...headers,
    },
    ...config,
  });
}
