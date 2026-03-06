package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

type Event struct { 
	conn net.Conn
	kind string
	data string
}

func main() {

	ch := make(chan Event) //unbuffered chan of type event

	listener , err := net.Listen("tcp" ,":9090")

	if err != nil { 
		fmt.Println("Failed to create server")
		os.Exit(1)
	}
	defer listener.Close()

	go manager(ch)
	startServer(listener , ch)
}

func handleClinet(conn net.Conn , ch chan Event) { 
	ch <- Event{conn: conn, kind: "join" , data: ""}

	defer conn.Close()
	scanner := bufio.NewScanner(conn)

	for scanner.Scan() { 
		ch <- Event{
			conn: conn,
			kind: "message",
			data: scanner.Text(),
		}
	}
	ch <- Event{conn: conn, kind: "leave" , data: ""}
}


func startServer(ln net.Listener, ch chan Event) { 
	for  { 
  		conn , err := ln.Accept()
		if err != nil{ 
			println("Failed to create connection!")
		}
		go handleClinet(conn, ch)
	}
 }

func manager(ch chan Event) { 
	conns := make(map[net.Conn]bool)
	for event := range ch { 
		switch event.kind { 
		case "join" : 
			if conns[event.conn] == false { 
				conns[event.conn] = true
			}
		case "leave": 
			delete(conns , event.conn)
		case "message": 
			for k := range conns { 
				if k != event.conn { 
					fmt.Fprintf(k, "%s\n", event.data)
				}
			}
		}
	}
}


