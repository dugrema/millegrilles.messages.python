METHOD_1 = """
import binascii

def printme(value: str):
   print("Printing %s" % value)

def printbin(value: str):
   hex_value = binascii.hexlify(value).decode('utf-8')
   print("Hex value: %s" % hex_value)
   
printme(input1)
printbin(input2)

ret_value = {"response": "Allo from inside"}
"""

def main():
    values = {"input1": "My value 2", "input2": b"01234"}
    compiled_code_1 = compile(METHOD_1, "<string>", "exec")
    exec(compiled_code_1, values)
    output = values['ret_value']
    print("Output from exec: %s" % output)

if __name__ == "__main__":
    main()
