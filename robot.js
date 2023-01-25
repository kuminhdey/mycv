var body = $response.body;
body = body.replace("black_list_", "");
console.log(body);
$done(body);
