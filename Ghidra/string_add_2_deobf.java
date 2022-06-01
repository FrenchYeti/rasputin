//Another string decryptor
//@author Fare9
//@category Unpacking
//@keybinding 
//@menupath 
//@toolbar 

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class Unpacking_string_add_2_deobf extends GhidraScript {

	List<Byte> originalBuffer = new ArrayList<Byte>();
	List<Byte> newBuffer = new ArrayList<Byte>();
	
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
	
	private String decrypt_sub(byte subKey, Address startAddress, Address endAddress)
	{
		String result = "";
		Address i;
		int j = 0;
		long size = endAddress.getOffset() - startAddress.getOffset() + 1;
		
		println("[!] Going to decrypt from " + startAddress.toString() +
				"to " + endAddress.toString() + " size " + String.valueOf(size) +
				" with key " + String.valueOf(subKey));
		
		i = startAddress;
		
		for(j = 0; j < size; j++)
		{
			println("[+] Accessing address " + i.toString() + "["+String.valueOf(j)+"]");
			
			byte read_byte, decrypted_byte;
			
			try {
				read_byte = getByte(i);
			} catch(MemoryAccessException mae)
			{
				println("[-] Error accessing address " + i.toString());
				break;
			}
			
			decrypted_byte = (byte) (read_byte - subKey - j);
			
			originalBuffer.add(read_byte);
			newBuffer.add(decrypted_byte);
			
			println("[!] Decrypted byte "+String.valueOf(read_byte)+" to "+decrypted_byte+"("+(char)decrypted_byte+")");
			result += (char)decrypted_byte;
			
			i = i.next();
		}
		
		return result;
	}
	
    @Override
    public void run() throws Exception {
        Address decryptStart;
        Address decryptEnd;
        String decryptedString;

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
        
        int decryptionInt = askInt("Key", "enter key (between 0 and 255");
        
        if (decryptionInt < 0 || decryptionInt > 255)
        {
        	println("[-] ERROR, key can only be a byte number (between 0 and 255)");
        	return;
        }
        
        byte decryptionKey = (byte)decryptionInt;
        
        decryptedString = decrypt_sub(decryptionKey, decryptStart, decryptEnd);
        
        println("[!] Decrypted string = " + decryptedString);
        
        boolean replace = askYesNo("replace or not", "Do you want to replace bytes (yes/no)?");
        
        if (replace)
        {
        	replace_buffer(decryptStart);
        }
        
    }
}
