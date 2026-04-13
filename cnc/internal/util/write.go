package util

import "net"

func WriteToConn(conn net.Conn, data string) {
	conn.Write([]byte(data))
}