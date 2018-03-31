package main

/* Describes the creation of binds and endpoints on the platform
 */
type Networking interface {
	CreateBind(port uint16) (Bind, uint16, error)
	CreateEndpoint(addr string) (Endpoint, error)
}
