package base64

import (
    "../../set1/base64"
    "bufio"
    "bytes"
    "io"
    "os"
)

func Decodepath(path string) ([]byte, error) {
    file, err := os.Open(path)
    if err != nil {
        return nil, err
    }

    buf := new(bytes.Buffer)

    reader := bufio.NewReader(file)
    for {
        line, err := reader.ReadBytes('\n')
        if err != nil {
            if err == io.EOF {
                break
            }
            return nil, err
        }

        buf.Write(line[:len(line)-1])
    }

    decoded, err := base64.Decode(string(buf.Bytes()))
    if err != nil {
        return nil, err
    }

    return decoded, nil
}
