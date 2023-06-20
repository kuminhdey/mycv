function FindProxyForURL(url, host) {
  // Cấu hình các quy tắc proxy dựa trên URL và host
  if (shExpMatch(url, "*.example.com/*")) {
    return "PROXY proxy.example.com:8080";
  }
  
  // Quy tắc mặc định: không sử dụng proxy
  return "DIRECT";
}
