# OpenEMR-MCP
An MCP server for OpenEMR

# Raw docker commands <TODO need to get the compose.yml working>

`docker network create openemr-net`
`docker run --name openemr --network openemr-net -p 8080:80 -p 4443:443 -d openemr/openemr:7.0.3`
`docker run --name some-mysql --network openemr-net -e MYSQL_ROOT_PASSWORD=password -p:3306:3306 -d mysql:9.4`

# You'll need to create a mysql user for the openemr DB or use the root user.  I used the root user for most of this as I couldn't get openemr to generate the DB with another user from another domain.  Likely a docker networking issue on my part.




