function FindProxyForURL(url, host) {
  // Cấu hình các quy tắc proxy dựa trên URL và host
  if (shExpMatch(url, "10.*")) {
    return "DIRECT";
  }
  
  // Quy tắc mặc định: không sử dụng proxy
  return "PROXY 10.133.93.63:8080";
}
