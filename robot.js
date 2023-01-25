var body = $response.body;
var obj = JSON.parse(body);

obj['result'] = obj['result'].replace("black_list_", "");;
body = JSON.stringify(obj);

console.log(body);

$done(body);
