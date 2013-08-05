package bgpdoop.analyzer.lib;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;

import p3.hadoop.common.util.BinaryUtils;
import p3.hadoop.common.util.EZBytes;

public class Bgp4mp_Message {
	
	/* BGP state - defined in RFC1771 */
	public static final int BGP_STATE_IDLE			= 1;
	public static final int BGP_STATE_CONNECT		= 2;
	public static final int BGP_STATE_ACTIVE		= 3;
	public static final int BGP_STATE_OPENSENT		= 4;
	public static final int BGP_STATE_OPENCONFIRM	= 5;
	public static final int BGP_STATE_ESTABLISHED	= 6;

	/* BGP message types */
	public static final int BGP_MSG_OPEN		        =   1;
	public static final int BGP_MSG_UPDATE		        =   2;
	public static final int BGP_MSG_NOTIFY		        =   3;
	public static final int BGP_MSG_KEEPALIVE	        =   4;
	public static final int BGP_MSG_ROUTE_REFRESH_01    =   5;
	public static final int BGP_MSG_ROUTE_REFRESH	    =  128;

	public class Incomplete {
	    int afi;
	    int orig_len;
	    Prefix prefix = new Prefix();   
	}

	/* BGP4MP_MESSAGE & BGP4MP_MESSAGE*/
	public long		peer_as;
	public long		local_as;
	public int		interface_index;
	public int		address_family;
	public String	peer_ip;
	public String	local_ip;
	public Bgp4mp_Attributes attribute = new Bgp4mp_Attributes();

	public byte[] attBytes; 
	
    /* BGP packet header fields */
	public int		size;
	public int		type;

    /* For OPEN packets */
	public int	version;
	public long	my_as;
	public int	hold_time;
	public String bgp_id;
	public int	opt_len;
	public byte[] opt_data;

    /* For UPDATE packets */
	public int		withdraw_count;
	public int		announce_count;
    public ArrayList<Prefix> withdraw = new ArrayList<Prefix>();
    public ArrayList<Prefix> announce = new ArrayList<Prefix>();

    /* For corrupt update dumps */
    public int cut_bytes;
    public Incomplete incomplete = new Incomplete();

    /* For NOTIFY packets */
    public int error_code;
    public int sub_error_code;
    public int notify_len;
    public int notify_data;
	
	EZBytes eb;
	int pos;

	private boolean process_zebra_bgp_message_notify() {		
	    error_code = BinaryUtils.byteToInt(eb.GetBytes(pos, 1)); pos+=1;
	    sub_error_code = BinaryUtils.byteToInt(eb.GetBytes(pos, 1)); pos+=1;
	    notify_len = size - 21;
	    notify_data = BinaryUtils.byteToInt(eb.GetBytes(pos, notify_len)); pos+=notify_len;
	    return true;
	}
	
	private boolean process_zebra_bgp_message_open(int asn_len) throws UnknownHostException {
		version = BinaryUtils.byteToInt(eb.GetBytes(pos, 1)); pos+=1;
	    my_as = BinaryUtils.ubyteToLong(eb.GetBytes(pos, asn_len)); pos+=asn_len;
		hold_time = BinaryUtils.byteToInt(eb.GetBytes(pos, 2)); pos+=2;
	    bgp_id = InetAddress.getByAddress(eb.GetBytes(pos, 4)).toString().substring(1); pos+=4;
	    opt_len = BinaryUtils.byteToInt(eb.GetBytes(pos, 1)); pos+=1;	
	    opt_data = eb.GetBytes(pos, opt_len); pos+=opt_len;
	    return true;
	}
	
	private boolean process_zebra_bgp_message_update(int asn_len, int expected) throws UnknownHostException {
		EZBytes new_eb;
		int len = BinaryUtils.byteToInt(eb.GetBytes(pos, 2)); pos+=2;	

		if(len>eb.getLength()-pos) len = eb.getLength()-pos;
		new_eb = new EZBytes(len);
		new_eb.PutBytes(eb.GetBytes(pos, len), 0, len);
		withdraw_count = attribute.read_prefix_list(new_eb, attribute.AFI_IP, withdraw, incomplete, len);
		
		incomplete.orig_len = 0;	
		pos+=len;
		int total = BinaryUtils.byteToInt(eb.GetBytes(pos, 2)); pos+=2;
		if(total>0) {
			new_eb = new EZBytes(total);
			if(eb.getLength()-pos < total)
				return false;
			new_eb.PutBytes(eb.GetBytes(pos, total), 0, total);
			attribute.parseAttributes(new_eb, incomplete, asn_len);	pos+=total;
		}
		
		len = eb.getLength()-pos;
		new_eb = new EZBytes(len);
		new_eb.PutBytes(eb.GetBytes(pos, len), 0, len);
	    announce_count = attribute.read_prefix_list(new_eb, attribute.AFI_IP, announce, incomplete, len);
	    pos+=(eb.getLength()-pos);
	    
	    return true;
	}	
	
	public boolean parseMessage(byte[] pdata, int asn_len) throws UnknownHostException{	
		
		eb = new EZBytes(pdata.length);
		eb.PutBytes(pdata, 0, pdata.length);
		pos = 0;

		peer_as = BinaryUtils.ubyteToLong(eb.GetBytes(pos, asn_len)); pos+=asn_len;
		local_as = BinaryUtils.ubyteToLong(eb.GetBytes(pos, asn_len)); pos+=asn_len;
		interface_index = BinaryUtils.byteToInt(eb.GetBytes(pos, 2)); pos+=2;
		address_family = BinaryUtils.byteToInt(eb.GetBytes(pos, 2)); pos+=2;
		
		switch(address_family){
		case 1:
			 // ipv4
			peer_ip = InetAddress.getByAddress(eb.GetBytes(pos, 4)).toString().substring(1); pos+=4;
			local_ip = InetAddress.getByAddress(eb.GetBytes(pos, 4)).toString().substring(1); pos+=4;
			break;
		case 2:
			peer_ip = Inet6Address.getByAddress(eb.GetBytes(pos, 16)).toString().substring(1); pos+=16;
			local_ip = Inet6Address.getByAddress(eb.GetBytes(pos, 16)).toString().substring(1); pos+=16;
			break;
		case 0xffff:
			pos+=12;
			break;
		default:
			return false;
		}
		
		int cur = 0;
		int tmp = 0xff;
		while(cur++<16){
			tmp&=eb.GetByte(pos); pos++;
		}
		if(tmp!=0xff) return false;
		
		int msglen = BinaryUtils.byteToInt(eb.GetBytes(pos, 2)); pos+=2;
		int expected = msglen - 16 - 2;
		int msgtype = BinaryUtils.byteToInt(eb.GetBytes(pos, 1)); pos+=1;
		
//		if(eb.getLength()-pos<msglen)	return false;
		
	    switch(msgtype) {
		case BGP_MSG_UPDATE:
		    return process_zebra_bgp_message_update(asn_len, expected);
		case BGP_MSG_OPEN:
		    return process_zebra_bgp_message_open(asn_len);
		case BGP_MSG_NOTIFY:
//		    return process_zebra_bgp_message_notify();
		case BGP_MSG_KEEPALIVE:			
		case BGP_MSG_ROUTE_REFRESH_01:
		case BGP_MSG_ROUTE_REFRESH:
		default:
		    return false;
	    }  
	}
		

	@Override
	public String toString(){
		StringBuilder sb = new StringBuilder();
		sb
		.append(peer_as).append("|")
		.append(local_as).append("|")
		.append(interface_index).append("|")
		.append(address_family).append("|")
		.append(peer_ip).append("|")
		.append(local_ip).append("|")
		.append("withdraw_count: "+withdraw_count).append("|");
		if(withdraw_count>0){
			for(Prefix prefix : withdraw)
				sb.append(prefix.prefix+"/"+prefix.prefix_len).append("|");
		}else
			sb.append("|");
				
		if(announce_count>0){
			sb.append("announceCnt: "+announce_count).append("|");
			for(Prefix prefix : announce)
				sb.append(prefix.prefix+"/"+prefix.prefix_len).append("|");
		}else{
			sb.append(attribute.getPrefix_fromMP_info());
		}
				
		sb.append("attribute: "+attribute.toString());
//		.append(new BytesWritable(eb.GetBytes(pos)).toString());	
		return sb.toString();
	}
}

