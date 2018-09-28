package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/detailyang/go-bcrypto"

	"github.com/copernet/copernicus/model/block"
	"github.com/copernet/copernicus/model/blockindex"
	"github.com/copernet/copernicus/model/outpoint"
	"github.com/copernet/copernicus/model/undo"
	"github.com/copernet/copernicus/model/utxo"
	"github.com/copernet/copernicus/util"
	"github.com/detailyang/go-bcrypto/secp256k1"
	. "github.com/detailyang/go-bprimitives"
	"github.com/detailyang/go-bscript"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/urfave/cli"
)

func genaddr() error {
	hash := NewRandomHash()
	pubkey, ok := secp256k1.PubkeyCreate(hash.Bytes())
	if !ok {
		return errors.New("unknow reason")
	}

	// pubkeyEncoded := bcrypto.Base58EncodeCheck(pubkey, 0)
	// wif := bcrypto.Base58EncodeCheck(hash.Bytes(), byte(bcrypto.Mainet))
	// pubekyhash160 := Hash160(pubkey)
	// oopubekyhash160 := append([]byte{0}, pubekyhash160...)
	// cs := DHash256(oopubekyhash160).TakeBytes(0, 4)
	// oopubekyhash160checksum := append(oopubekyhash160, cs...)

	fmt.Printf("0 - Private ECDSA Key:\n")
	fmt.Printf("%s\n", hash.String())
	fmt.Printf("1 - Public ECDSA Key\n")
	fmt.Printf("%s\n", hex.EncodeToString(pubkey))
	fmt.Printf("2 - SHA-256 hash of 1\n")
	fmt.Printf("%s\n", Hash256(pubkey).String())
	fmt.Printf("3 - RIPEMD-160 Hash of 2\n")
	fmt.Printf("%s\n", hex.EncodeToString(Hash160(pubkey)))
	fmt.Printf("4 - Adding network bytes to 3\n")
	step3 := Hash160(pubkey)
	step4 := append([]byte{0x00}, step3...)
	fmt.Printf("%s\n", hex.EncodeToString(step4))
	fmt.Printf("5 - SHA-256 hash of 4\n")
	fmt.Printf("%s\n", hex.EncodeToString(Hash256(step4).Bytes()))
	fmt.Printf("6 - SHA-256 hash of 5\n")
	fmt.Printf("%s\n", hex.EncodeToString(DHash256(step4).Bytes()))
	fmt.Printf("7 - First four bytes of 6\n")
	step7 := DHash256(step4).TakeBytes(0, 4)
	fmt.Printf("%s\n", hex.EncodeToString(step7))
	fmt.Printf("8 - Adding 7 at the end of 4\n")
	step8 := append(step4, step7...)
	fmt.Printf("%s\n", hex.EncodeToString(step8))
	fmt.Printf("9 - Base58 encoding of 8\n")
	fmt.Printf("%s\n", bcrypto.Base58Encode(step8))

	// fmt.Printf("private           key:%s\n", hash.String())
	// fmt.Printf("private key       WIF:%s\n", wif)
	// fmt.Printf("public            key:%s\n", hex.EncodeToString(pubkey))
	// fmt.Printf("public encoded    key:%s\n", pubkeyEncoded)
	// fmt.Printf("public hash160    key:%s\n", hex.EncodeToString(pubekyhash160))
	// fmt.Printf("public hex    address:%s\n", hex.EncodeToString(oopubekyhash160checksum))
	// fmt.Printf("public base58 address:%s\n", bcrypto.Base58Encode(oopubekyhash160checksum))

	return nil
}

func disassemble(hexstring string) error {
	script, err := bscript.NewScriptFromHexString(hexstring)
	if err != nil {
		return err
	}

	disassembler := bscript.NewDisassembler()
	code, err := disassembler.Disassemble(script)
	if err != nil {
		return err
	}

	fmt.Println(code)

	return nil
}

func evalScript(s string) error {
	script, err := bscript.NewScriptFromString(s)
	if err != nil {
		return err
	}

	// TODO: support trace
	return bscript.EvalScript(script, 0, nil)
}

func parseDatFile(filename string) error {
	f, err := os.OpenFile(filename, os.O_RDONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	i := 0
	for {
		i++
		fmt.Println("i:", i)
		size, err := util.BinarySerializer.Uint32(f, binary.LittleEndian)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		data := make([]byte, size)
		if _, err = f.Read(data); err != nil {
			return err
		}

		b := block.NewBlock()
		if err := b.Unserialize(bytes.NewBuffer(data)); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		fmt.Println(b.Header.String())

		for _, tx := range b.Txs {
			fmt.Println(tx.String())
		}
	}

	return nil
}

var (
	obfuscateKeyKey = "\000obfuscate_key"
	obfuscateKeyLen = 8
)

func xor(val, obkey []byte) {
	if len(obkey) == 0 {
		return
	}
	for i, j := 0, 0; i < len(val); i++ {
		val[i] ^= obkey[j]
		j++
		if j == len(obkey) {
			j = 0
		}
	}
}

func parseIndexDir(filename string) error {
	db, err := leveldb.OpenFile(filename, &opt.Options{ErrorIfExist: false})
	if err != nil {
		return err
	}
	defer db.Close()

	obkey, err := db.Get([]byte(obfuscateKeyKey), nil)
	if err != nil {
		return err
	}

	hash := util.Hash{}
	key := make([]byte, 0, 100)
	key = append(key, 'b')
	key = append(key, hash[:]...)
	iter := db.NewIterator(nil, nil)
	defer iter.Release()

	for ok := iter.Seek(key); ok; ok = iter.Next() {
		k := iter.Key()

		if k == nil || k[0] != 'b' {
			break
		}

		v := iter.Value()
		xor(v, obkey)

		var bi = blockindex.NewBlockIndex(block.NewBlockHeader())
		if err := bi.Unserialize(bytes.NewBuffer(v)); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		fmt.Println("k:v", k, bi)
	}
	return iter.Error()
}

func parseRevFile(filename string) error {
	f, err := os.OpenFile(filename, os.O_RDONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	i := 0
	for {
		i++
		fmt.Println("index:", i)
		size, err := util.BinarySerializer.Uint32(f, binary.LittleEndian)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if size == 0 {
			break
		}

		buf := make([]byte, size)
		num, err := f.Read(buf)
		if uint32(num) < size {
			fmt.Println("shit")
			return err
		}

		undocoin := undo.NewBlockUndo(0)
		undoData := buf[:len(buf)-32]
		buff := bytes.NewBuffer(undoData)
		err = undocoin.Unserialize(buff)
		if err != nil {
			if err == io.EOF {
				continue
			}
			return err
		}

		txundos := undocoin.GetTxundo()
		for _, txundo := range txundos {
			for _, undocoin := range txundo.GetUndoCoins() {
				fmt.Println("undo: ", undocoin, len(txundo.GetUndoCoins()), undocoin.GetHeight())
			}
		}
	}

	return nil
}

func parsechainstate(filename string) error {
	db, err := leveldb.OpenFile(filename, &opt.Options{ErrorIfExist: false})
	if err != nil {
		return err
	}
	defer db.Close()

	obkey, err := db.Get([]byte(obfuscateKeyKey), nil)
	if err != nil {
		return err
	}

	v, err := db.Get([]byte{'B'}, nil)
	if err != nil {
		return err
	}

	xor(v, obkey)

	hashBlock := new(util.Hash)
	_, err = hashBlock.Unserialize(bytes.NewBuffer(v))
	if err != nil {
		return err
	}

	fmt.Println("bestchaintip", hashBlock)

	hash := util.Hash{}
	key := make([]byte, 0, 100)
	key = append(key, 'C')
	key = append(key, hash[:]...)
	iter := db.NewIterator(nil, nil)
	defer iter.Release()

	for ok := iter.Seek(key); ok; ok = iter.Next() {
		k := iter.Key()
		if k == nil || k[0] != 'C' {
			break
		}

		op := &outpoint.OutPoint{}
		err := op.Unserialize(bytes.NewBuffer(k))
		if err != nil {
			return err
		}

		v := iter.Value()
		xor(v, obkey)

		utxoentry := utxo.NewEmptyCoin()
		err = utxoentry.Unserialize(bytes.NewBuffer(v))
		if err != nil {
			return err
		}

		fmt.Println("utxo coin", utxoentry.GetHeight(), utxoentry.GetAmount(), op.String())

		// txout := utxoentry.GetTxOut()
		// fmt.Println("txout", txout.)
	}

	return iter.Error()
}

func main() {
	app := cli.NewApp()
	app.Name = "coper-toolkit"
	app.Usage = ""
	app.Description = "personal copernicus toolkit to analyze something, use at your own risk:)"
	app.Version = "0.1.0"

	app.Commands = []cli.Command{
		{
			Name:  "parsedat",
			Usage: "parse dat file",
			Action: func(c *cli.Context) error {
				filename := c.Args().First()
				return parseDatFile(filename)
			},
		},
		{
			Name:  "parserev",
			Usage: "parse rev file",
			Action: func(c *cli.Context) error {
				filename := c.Args().First()
				return parseRevFile(filename)
			},
		},
		{
			Name:  "parseindex",
			Usage: "parse index dir",
			Action: func(c *cli.Context) error {
				filename := c.Args().First()
				return parseIndexDir(filename)
			},
		},
		{
			Name:  "parsechainstate",
			Usage: "parse chainstate",
			Action: func(c *cli.Context) error {
				filename := c.Args().First()
				return parsechainstate(filename)
			},
		},
		{
			Name:  "evalscript",
			Usage: "eval script",
			Action: func(c *cli.Context) error {
				hexstring := c.Args().First()
				return evalScript(hexstring)
			},
		},
		{
			Name:  "disassemble",
			Usage: "disassemble script",
			Action: func(c *cli.Context) error {
				hexstring := c.Args().First()
				return disassemble(hexstring)
			},
		},
		{
			Name:  "genaddr",
			Usage: "generate public and private key",
			Action: func(c *cli.Context) error {
				return genaddr()
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
