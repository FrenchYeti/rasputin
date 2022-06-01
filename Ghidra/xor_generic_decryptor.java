//Script to deobfuscate xor giving an array of bytes as content and other as key, this will allow applying decryption.
//If key is shorter than content, once reached max size of the key, the first index will be taken.
//@author Farenain
//@category Decryptor
//@keybinding 1
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;

public class xor_generic_decryptor extends GhidraScript {
	List<Byte> originalBuffer = new ArrayList<Byte>();
	List<Byte> newBuffer = new ArrayList<Byte>();
	List<Byte> keyBUffer = new ArrayList<Byte>();
	
	private void replace_buffer(Address startAddress)
	{
		Address i;
		int j = 0;
		
		i = startAddress;
		
		for (j = 0; j < newBuffer.size(); j++)
		{
			println("[+] Replacing byte " + originalBuffer.get(j).toString() + " in address "+i.toString()+" with decrypted byte " + newBuffer.get(j).toString());
			byte new_byte = newBuffer.get(j);
			
			try {
				setByte(i, new_byte);
			} catch(MemoryAccessException mae)
			{
				println("[-] Error accessing address " + i.toString());
				break;
			}
			
			i = i.next();
		}
	}
	
	private String decrypt_xor(Address startAddress, Address endAddress, Address keyStart, Address keyEnd)
	{
		String result = "";
		Address accessed_byte;
		Address accessed_key = keyStart;
		int index_byte = 0;
		long size = endAddress.getOffset() - startAddress.getOffset();		
		long key_size = keyEnd.getOffset() - keyStart.getOffset();
		
		accessed_byte = startAddress;
		
		for (index_byte = 0; index_byte <= size; index_byte++)
		{
			println("[+] Accessing address: " + accessed_byte.toString() + "[" + String.valueOf(index_byte) + "]");
			
			byte read_byte, decrypted_byte, key_byte;
			
			// read the bytes to use
			try {
				read_byte = getByte(accessed_byte);
				key_byte = getByte(accessed_key);
			} catch(MemoryAccessException mae)
			{
				println("[-] Error accessing address: " + accessed_byte.toString());
				break;
			}
			// decrypt bytes
			decrypted_byte = (byte) (read_byte ^ key_byte);
			originalBuffer.add(read_byte);
			newBuffer.add(decrypted_byte);
			
			println("[!] Decrypted byte "+String.valueOf(read_byte)+" to "+decrypted_byte+"("+(char)decrypted_byte+") with key: " + key_byte);
			result += (char)decrypted_byte;
			
			accessed_byte = accessed_byte.next();
			
			if (accessed_key.getAddressableWordOffset() == keyEnd.getAddressableWordOffset())
				accessed_key = keyStart;
			else
				accessed_key = accessed_key.next();
		}
		
		
		return result;
	}
	
	@Override
	protected void run() throws Exception {
		Address decryptStart;
        Address decryptEnd;
        String decryptedString;

        println("\"xor_generic_decryptor\"Script to decrypt a selection of bytes\n" +
                "using xor decryption routine and a given key based in a range address.\n"+
        		"Created by Fare9!.");
        
        if(currentSelection != null)
        {
            decryptStart = currentSelection.getMinAddress();
            decryptEnd = currentSelection.getMaxAddress();
            
            println("[!] Obtained address: "+String.valueOf(decryptStart)+" - "+String.valueOf(decryptEnd));
        }
        else
        {
        	println("Please select a starting address and ending address\n" + 
        			"in order to apply the decryption.");
        	return;
        }
        
        Address keyStart = askAddress("keyStart", "Insert key address start");
        Address keyEnd = askAddress("keyEnd", "Insert key address end");
        
        decryptedString = decrypt_xor(decryptStart, decryptEnd, keyStart, keyEnd);
        
        println("[!] Decrypted string = " + decryptedString);
        
        boolean replace = askYesNo("replace or not", "Do you want to replace bytes (yes/no)?");
        
        if (replace)
        {
        	replace_buffer(decryptStart);
        }
	}
	
}
