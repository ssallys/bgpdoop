package bgpdoop.analyzer.lib;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Calendar;

import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.record.Buffer;

import bgpdoop.analyzer.lib.Tabledumpv2_PeerEntry.PeerEntry;

import p3.hadoop.common.util.BinaryUtils;
import p3.hadoop.common.util.Bytes;
import p3.hadoop.common.util.EZBytes;


/** This class represents TCP packet. */
public class Tabledump_Mrtd 
{
	/* RIB Entry */
	public int view;
	public int seqno;
	public String prefix;
	public int prefixLen;
	public int status;
	public String oriTime;
	public long ldate = 0;
	public String pAddr;
	public long pAS;
	public int attLen;
	public Bgp4mp_Attributes attribute;
	
	EZBytes eb;
	int pos;
	Calendar cal = Calendar.getInstance();

	public boolean parseRibEntry(byte[] pdata, int ipv, int asLen) throws UnknownHostException{	
		
		eb = new EZBytes(pdata.length);
		eb.PutBytes(pdata, 0, pdata.length);
		pos = 0;
		
		this.view = BinaryUtils.byteToInt(eb.GetBytes(pos, 2)); pos+=2;
		this.seqno = BinaryUtils.byteToInt(eb.GetBytes(pos, 2)); pos+=2;
		if(ipv==4){
			this.prefix = InetAddress.getByAddress(eb.GetBytes(pos, 4)).toString().substring(1); pos+=4;
		}else if(ipv==16){
			this.prefix = Inet6Address.getByAddress(eb.GetBytes(pos, 16)).toString(); pos+=16;
		}
		this.prefixLen = BinaryUtils.byteToInt(eb.GetBytes(pos,1)); pos+=1;
		this.status = BinaryUtils.byteToInt(eb.GetBytes(pos,1)); pos+=1;
		
		ldate = BinaryUtils.ubyteToLong(eb.GetBytes(pos,4)); pos+=4;
		cal.setTimeInMillis(ldate*1000);
		oriTime = String.format(String.format("%1$tY-%1$tm-%1$td.%1$tH%1$tM", cal));
		if(ipv==4){
			this.pAddr = InetAddress.getByAddress(eb.GetBytes(pos, 4)).toString(); pos+=4;
		}else if(ipv==16){
			this.pAddr = Inet6Address.getByAddress(eb.GetBytes(pos, 16)).toString(); pos+=16;
		}
		this.pAS = BinaryUtils.byteToInt(eb.GetBytes(pos, 2)); pos+=2;		
		this.attLen = BinaryUtils.byteToInt(eb.GetBytes(pos,2)); pos+=2;
		if(attLen>0){
			attribute = new Bgp4mp_Attributes();
			EZBytes new_eb = new EZBytes(attLen);
			if(eb.getLength()-pos < attLen)
				return false;
			new_eb.PutBytes(eb.GetBytes(pos, eb.getLength()-pos), 0, attLen);
			attribute.parseAttributes(new_eb, null, asLen);
		}
		
	    return true;
	}
	
	public String toString(){
		StringBuilder sb = new StringBuilder();
		sb
		.append(seqno).append("|")
		.append(prefix).append("/")
		.append(prefixLen).append("|")
//		.append(new BytesWritable(eb.GetBytes(0)).toString()).append("|");	

		.append(status).append("|")
		.append(oriTime).append("|")
		.append(pAddr).append("|")
		.append(pAS).append("|")
		.append(attLen).append("|");
		
		if(attLen>0)
			sb.append("attr-->")
			.append(attribute.toString());
						
		return sb.toString();
	}
}