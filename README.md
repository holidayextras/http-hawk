Hawk Http
===
A HTTP Connector with optional [HAWK authentication](https://github.com/hueniverse/hawk).

Usage
---
```php
$http = new HttpHawk(array(
	"server" => "my.server.com",
	"auth" => array(
		"secretKey" => "**secret key here**",
		"accessKey" => "**access key here**"
	)
));

$result = $http->request( 'get', 'your/endpoint', array( "your" => "data", "passed" => "in" ) );

// Now you can use the body response
var_dump( $result['body'] );
```