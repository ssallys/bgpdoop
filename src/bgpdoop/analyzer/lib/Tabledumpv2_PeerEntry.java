package bgpdoop.analyzer.lib;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;

import org.apache.hadoop.io.Text;
import org.apache.hadoop.record.Buffer;

import p3.hadoop.common.util.BinaryUtils;
import p3.hadoop.common.util.Bytes;
import p3.hadoop.common.util.EZBytes;


/** This class represents TCP packet. */
public class Tabledumpv2_PeerEntry 
{
	/* Peer Entry */
	public long cid;
	public String vname;
	public int peerCnt;
	public ArrayList<PeerEntry> peerEntries = new ArrayList<PeerEntry>();
	
	public class PeerEntry{
		public long pbid;
		public String pAddr;
		public long pAS;
	}
	
	EZBytes eb;
	int pos;
	
	public static final int AFI_IP=1;
	public static final int AFI_IP6=2;
	public static final int BGPDUMP_PEERTYPE_TABLE_DUMP_V2_AS4=2;
	
	public int parsePIT(byte[] pdata) throws UnknownHostException{	
		
		int astype = 0;
		eb = new EZBytes(pdata.length);
		eb.PutBytes(pdata, 0, pdata.length);
		pos = 0;
		
		this.cid = BinaryUtils.ubyteToLong(eb.GetBytes(pos, 4)); pos+=4;
		int vnlen = BinaryUtils.byteToInt(eb.GetBytes(pos,2)); pos+=2;
		if(vnlen>0){
			this.vname = new String(eb.GetBytes(pos, vnlen), Charset.forName("UTF-8")); pos+=vnlen;	
		}
		this.peerCnt = BinaryUtils.byteToInt(eb.GetBytes(pos,2)); pos+=2;
		
		int cnt=0;
		int peerType = 0;
		PeerEntry peerEntry;
		
		while(cnt<peerCnt){
			
			peerEntry = new PeerEntry();
			peerType = BinaryUtils.byteToInt(eb.GetBytes(pos, 1),1); pos+=1;
			peerEntry.pbid = BinaryUtils.ubyteToLong(eb.GetBytes(pos, 4)); pos+=4;
			
//			if((peerType&0x80)==0x80){ // ipv4
				peerEntry.pAddr = InetAddress.getByAddress(eb.GetBytes(pos, 4)).toString(); pos+=4;
//			}else{
//				peerEntry.pAddr = Inet6Address.getByAddress(eb.GetBytes(pos, 16)).toString(); pos+=16;
//			}
			if((peerType&BGPDUMP_PEERTYPE_TABLE_DUMP_V2_AS4)==BGPDUMP_PEERTYPE_TABLE_DUMP_V2_AS4){ // 16bit AS
				peerEntry.pAS = BinaryUtils.ubyteToLong(eb.GetBytes(pos, 4)); pos+=4;
				astype = 4;
			}else{
				peerEntry.pAS = BinaryUtils.ubyteToLong(eb.GetBytes(pos, 2)); pos+=2;
				astype = 2;
			}	
			
			peerEntries.add(peerEntry);
			cnt++;
		}
	    return astype;
	}

	public String toString(){
		StringBuilder sb = new StringBuilder();
		sb
		.append(cid).append("|")
		.append(vname).append("|")
		.append(peerCnt).append("|");
		
		for(PeerEntry peerEntry: peerEntries)
			sb.append(peerEntry.pbid).append(" ")
			.append(peerEntry.pAddr).append(" ")
			.append(peerEntry.pAS).append(" ");	
				
		return sb.toString();
	}
}