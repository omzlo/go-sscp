package sscp

func Concat(slices ...[]byte) []byte {
    tlen := 0
    for _, slice := range slices {
        tlen += len(slice)
    }
    r := make([]byte, tlen)
    p := 0
    for _, slice := range slices {
        copy(r[p:], slice)
        p += len(slice)
    }
    return r
}
