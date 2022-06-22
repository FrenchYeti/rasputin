
// Poor script to fix decompiler issue by replacing B(L)R xA by B(L) val(xA) when xA is computed
//
// @author FrenchYeti
// @category Unpacking
// @keybinding
// @menupath
// @toolbar

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblyException;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.ProgramSelection;


public class patch_computed_branch_arm64 extends GhidraScript {

    Assembler asm;
    long baseAddr;

    String[] branchOp = new String[]{ "blr", "br" };
    String[] patchOp = new String[]{ "bl", "b" };

    private String getReplaceOp( String instrOp){
        String op = null;
        for(int i=0; i<this.branchOp.length; i++){
            if(instrOp.equals(this.branchOp[i])){
                op = this.patchOp[i];
            }
        }

        return op;
    }

    private void searchFixedBranch( Address beginAddr, Address endAddr, boolean doPatch ) {

        Listing prog = currentProgram.getListing();
        ProgramSelection addrSet = new ProgramSelection( beginAddr, endAddr);
        CodeUnitIterator iter = prog.getCodeUnits( addrSet, true);
        CodeUnit code;
        Reference[] refs;
        String newBrOp = null;

        int ctrAll = 0;
        int ctrPatch = 0;

        println("[-] Scanning ... ");

        while(iter.hasNext()){
            code = iter.next();

            newBrOp = this.getReplaceOp(code.getMnemonicString());

            if(newBrOp==null) continue;

            refs = code.getReferencesFrom();
            ctrAll++;

            if( refs.length == 0){
                println("[+] 0 Ref found at " + code.getAddress().toString("0x"));

            }else{
                println("[+] "+refs.length+" Ref found at " + code.getAddress().toString("0x")+"   "+code.getMnemonicString());
                for(int i=0; i<refs.length; i++){
                    String type = refs[i].getReferenceType().getName();
                    println("  - '"+type+"' to " + refs[i].getToAddress().toString());

                    if(!type.startsWith("COMPUTED_")) continue;

                    ctrPatch++;
                    if(refs.length==1 && doPatch){
                        this.patch( newBrOp, code.getAddress(), refs[i].getToAddress());
                    }
                }
            }


            newBrOp = null;
        }


        println("[+] Jumps found : "+ctrAll+" , Patchable jumps : "+ctrPatch);
    }

    private void patch( String newOp, Address pBranchAddr, Address pToAddress){
        String rel = pToAddress.toString("0x");

        try{
            println("     [+] Patch opcode : change 'B(L)R x?' by "+newOp+" "+rel);
            this.asm.assemble( pBranchAddr, newOp+" "+ rel);
            println("     [!] Opcode patched ");
        }catch(AssemblyException | MemoryAccessException | AddressOverflowException e){
            println("     [-] Error while patching : "+e.getMessage());
        }
    }

    private void patchBlrAt( Address pBranchAddr)  {

        Listing prog;
        CodeUnit instr;
        ReferenceIterator iter;
        Reference[] refs;
        String newBrOp = null;

        prog = currentProgram.getListing();
        instr = prog.getCodeUnitAt( pBranchAddr);


        newBrOp = this.getReplaceOp(instr.getMnemonicString());

        if(newBrOp==null){
            println("[-] Error unsupported instruction '"+instr.getMnemonicString()+"' at  " + pBranchAddr.toString());
        }


        println("[+] Jump found '"+instr.getMnemonicString()+"' at  " + pBranchAddr.toString());
        refs = instr.getReferencesFrom();

        if(refs.length>0){
            String type = refs[0].getReferenceType().getName();
            println("[+] Ref found '"+type+"' of  " + refs[0].getToAddress().toString());
            if(refs.length==1 && type.equals("COMPUTED_CALL")){
                this.patch( newBrOp, pBranchAddr, refs[0].getToAddress());
            }
        }
    }

    @Override
    public void run() throws Exception {
        Address begin;
        Address end;
        String decryptedString;

        this.asm = Assemblers.getAssembler(currentProgram);
        this.baseAddr = currentProgram.getImageBase().getOffset();

        boolean doPatch = askYesNo("Patch jumps", "Are you sure to patch jumps when target is known (yes/no) ?");
        boolean scanAll = false;

        if(currentAddress != null && currentSelection==null)
        {
            scanAll = askYesNo("Patch jumps : Scan entire program ?", "Do you want to search in the entire program (yes/no) ?");

            if(scanAll){
                MemoryBlock block = currentProgram.getMemory().getBlock(".text");
                if(block != null){
                    this.searchFixedBranch( block.getStart(), block.getEnd(), doPatch);
                }else{
                    println("[-] Error : memory range '.text' not found ");
                }

                return;
            }

            if(doPatch){
                this.patchBlrAt(currentAddress);
            }else{
                println("[-] Nothing to do ");
            }

            return;
        }

        if(currentSelection != null)
        {
            begin = currentSelection.getMinAddress();
            end = currentSelection.getMaxAddress();

            if(end.subtract(begin)<5){
                if(doPatch){
                    this.patchBlrAt(currentAddress);
                }else{
                    println("[-] Nothing to do ");
                }

                return;
            }

            this.searchFixedBranch( begin, end, doPatch);
            return;
        }


    }
}
