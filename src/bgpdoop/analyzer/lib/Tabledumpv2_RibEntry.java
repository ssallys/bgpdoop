package bgpdoop.analyzer.lib;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Calendar;


import p3.hadoop.common.util.BinaryUtils;
import p3.hadoop.common.util.EZBytes;


/** This class represents TCP packet. */
public class Tabledumpv2_RibEntry 
{
	/* RIB Entry */
	public long seqno;
	public int prefixLen;
	public String prefix;
	public int entryCnt;
	public ArrayList<RIBEntry> ribEntries = new ArrayList<RIBEntry>();
	
	public class RIBEntry{
		public long pidx;
		public String oriTime;
		public long ldate;
		public int attLen;
		public Bgp4mp_Attributes attribute;
	}	
	
	EZBytes eb;
	int pos;
	
	public int parseRibEntry(byte[] pdata, int asn_len) throws UnknownHostException{	
		
		eb = new EZBytes(pdata.length);
		eb.PutBytes(pdata, 0, pdata.length);
		pos = 0;
		Calendar cal = Calendar.getInstance();
		
		this.seqno = BinaryUtils.ubyteToLong(eb.GetBytes(pos, 4)); pos+=4;
		this.prefixLen = BinaryUtils.byteToInt(eb.GetBytes(pos,1)); pos+=1;
		if(prefixLen>0){
			int part = prefixLen%8;
			int readbyte = (prefixLen+7)/8;

	        byte[] bprefix = new byte[4];
	        System.arraycopy(eb.GetBytes(pos, readbyte), 0, bprefix, 0, readbyte);
	        this.prefix = InetAddress.getByAddress(bprefix).toString().substring(1);  pos+=readbyte; 
		}
		this.entryCnt = BinaryUtils.byteToInt(eb.GetBytes(pos,2)); pos+=2;
				
		int cnt=0;
		RIBEntry ribEntry;
		while(cnt<entryCnt){
			ribEntry = new RIBEntry();
			ribEntry.pidx = BinaryUtils.byteToInt(eb.GetBytes(pos,2)); pos+=2;
			
			ribEntry.ldate = BinaryUtils.ubyteToLong(eb.GetBytes(pos,4)); pos+=4;
			cal.setTimeInMillis(ribEntry.ldate*1000);
			ribEntry.oriTime = String.format(String.format("%1$tY-%1$tm-%1$td.%1$tH%1$tM", cal));
			ribEntry.attLen = BinaryUtils.byteToInt(eb.GetBytes(pos,2)); pos+=2;
			if(ribEntry.attLen>0){
				ribEntry.attribute = new Bgp4mp_Attributes();
				EZBytes new_eb = new EZBytes(ribEntry.attLen);
				if(eb.getLength()-pos < ribEntry.attLen)
					return 0;
				new_eb.PutBytes(eb.GetBytes(pos, ribEntry.attLen), 0, ribEntry.attLen);
				ribEntry.attribute.parseAttributes(new_eb, null, asn_len);
				pos+=ribEntry.attLen;
			}
			ribEntries.add(ribEntry);
			cnt++;
		}		
	    return cnt;
	}
	
	public String toString(){
		StringBuilder sb = new StringBuilder();
		sb
		.append("seqno->"+seqno).append("|")
		.append("prefix->"+prefix).append("/")
		.append(prefixLen).append("|");
//		.append(new BytesWritable(eb.GetBytes(0)).toString()).append("|");	

		for(RIBEntry ribEntry: ribEntries)
			sb.append("peerID->"+ribEntry.pidx).append(" ")
			.append("oriTime->"+ribEntry.oriTime).append(" ")
			.append(ribEntry.attLen).append(" ").append("|")
			.append(ribEntry.attribute.toString());			
						
		return sb.toString();
	}
}