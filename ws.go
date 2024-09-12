package WS

import (
	"fmt"
	"crypto/sha1"
	"net"
	"net/http"
	"encoding/base64"
	"strings"
)

func Upgrader(w http.ResponseWriter, r *http.Request) net.Conn {
	if strings.ToLower(r.Header.Get("Upgrade")) != "websocket" {
		return nil
	}
	webSocketKey := r.Header.Get("Sec-WebSocket-Key")
	if webSocketKey == "" {
		http.Error(w, "400 Bad Request - Missing Sec-WebSocket-Key", http.StatusBadRequest)
		return nil
	}

	fmt.Printf("Sec-WebSocket-Key: %s\n", webSocketKey)
	acceptKey := generateAcceptKey(webSocketKey)
	w.Header().Set("Upgrade", "websocket")
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Sec-WebSocket-Accept", acceptKey)
	w.WriteHeader(http.StatusSwitchingProtocols)

	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, "500 Internal Server Error: Failed to hijack connection", http.StatusInternalServerError)
		return nil
	}
	return conn
}

func generateAcceptKey(key string) string {
	const magicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + magicGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func ReadFrame(conn net.Conn) ([]byte, error) {
	// The first byte contains the FIN bit and opcode, the second byte contains the masking key
	header := make([]byte, 2)
	_, err := conn.Read(header)
	if err != nil {
		return nil, err
	}

	opcode := header[0] & 0x0F
	if opcode == 0x8 {
		return []byte{}, nil
	}

	payloadLen := int(header[1] & 0x7F) 

	var maskKey [4]byte
	if payloadLen == 126 {
		_, err = conn.Read(header[:2])
		if err != nil {
			return nil, err
		}
		payloadLen = int(header[0])<<8 | int(header[1])
	} else if payloadLen == 127 {
			extendedLength := make([]byte, 8)
			_, err = conn.Read(extendedLength)
			if err != nil {
				return nil, err
			}
	}

	if header[1]&0x80 == 0x80 {
		_, err = conn.Read(maskKey[:])
		if err != nil {
			return nil, err
		}
	}

	payload := make([]byte, payloadLen)
	_, err = conn.Read(payload)
	if err != nil {
		return nil, err
	}

	// apply mask
	if header[1]&0x80 == 0x80 {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return payload, nil
}


func WriteFrame(conn net.Conn, payload []byte) error {
	frameHeader := []byte{0x81} // FIN bit set, opcode 1 (text frame)
	payloadLen := len(payload)

	if payloadLen <= 125 {
		frameHeader = append(frameHeader, byte(payloadLen))
	} else if payloadLen <= 65535 {
		frameHeader = append(frameHeader, 126, byte(payloadLen>>8), byte(payloadLen))
	} else {
		return fmt.Errorf("payload length exceeds 65535")
	}

	_, err := conn.Write(frameHeader)
	if err != nil {
		return err
	}

	_, err = conn.Write(payload)
	return err
}

