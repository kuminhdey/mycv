function FindProxyForURL(url, host) {
  // Kiểm tra nếu URL bắt đầu bằng "http://10.133.178.83:8080/"
  if (shExpMatch(url, "http://10.133.178.83:8080/*")) {
    return "DIRECT";
  }
  
  // Mặt khác, sử dụng proxy 10.133.93.63:8080
  return "PROXY 10.133.93.63:8080";
}
