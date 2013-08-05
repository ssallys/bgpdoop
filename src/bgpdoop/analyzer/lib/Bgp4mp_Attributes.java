package bgpdoop.analyzer.lib;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;

import bgpdoop.analyzer.lib.Bgp4mp_Message.Incomplete;
import p3.hadoop.common.util.BinaryUtils;
import p3.hadoop.common.util.EZBytes;

public class Bgp4mp_Attributes {
	
	/* BGP Attribute flags. */
	public static final int BGP_ATTR_FLAG_OPTIONAL  = 0x80;	/* Attribute is optional. */
	public static final int BGP_ATTR_FLAG_TRANS     = 0x40;	/* Attribute is transitive. */
	public static final int BGP_ATTR_FLAG_PARTIAL   = 0x20;	/* Attribute is partial. */
	public static final int BGP_ATTR_FLAG_EXTLEN    = 0x10;	/* Extended length flag. */
	
	/* BGP attribute type codes.  */
	public static final int BGP_ATTR_ORIGIN 		=  1;
	public static final int BGP_ATTR_AS_PATH 		=  2;
	public static final int BGP_ATTR_NEXT_HOP 		=  3;
	public static final int BGP_ATTR_MULTI_EXIT_DISC=  4;
	public static final int BGP_ATTR_LOCAL_PREF		=  5;
	public static final int BGP_ATTR_ATOMIC_AGGREGATE= 6;
	public static final int BGP_ATTR_AGGREGATOR		=  7;
	public static final int BGP_ATTR_COMMUNITIES	=  8;
	public static final int BGP_ATTR_ORIGINATOR_ID	=  9;
	public static final int BGP_ATTR_CLUSTER_LIST	= 10;
	public static final int BGP_ATTR_DPA 			= 11;
	public static final int BGP_ATTR_ADVERTISER		= 12;
	public static final int BGP_ATTR_RCID_PATH		= 13;
	public static final int BGP_ATTR_MP_REACH_NLRI	= 14;
	public static final int BGP_ATTR_MP_UNREACH_NLRI= 15;
	public static final int BGP_ATTR_EXT_COMMUNITIES= 16;
	public static final int BGP_ATTR_NEW_AS_PATH	= 17;
	public static final int BGP_ATTR_NEW_AGGREGATOR=  18;
	
	/* BGP ASPATH attribute defines */
	public static final int AS_HEADER_SIZE    =2;

	public static final int AS_SET            =1;
	public static final int AS_SEQUENCE       =2;
	public static final int AS_CONFED_SEQUENCE=3;
	public static final int AS_CONFED_SET    = 4;

	public static final int AS_SEG_START 	 = 0;
	public static final int AS_SEG_END 		 = 1;

	public static final int ASPATH_STR_DEFAULT_LEN = 32;
	public static final String ASPATH_STR_ERROR    =  "! Error !";

	/* BGP COMMUNITY attribute defines */
	public static final int COMMUNITY_NO_EXPORT           =  0xFFFFFF01;
	public static final int COMMUNITY_NO_ADVERTISE        =  0xFFFFFF02;
	public static final int COMMUNITY_NO_EXPORT_SUBCONFED =  0xFFFFFF03;
	public static final int COMMUNITY_LOCAL_AS            =  0xFFFFFF03;
	
	/* MP-BGP address families */
	public static final int AFI_IP = 1;
	public static final int AFI_IP6 = 2;
	public static final int BGPDUMP_MAX_AFI = AFI_IP6;
	public static final int SAFI_UNICAST = 1;
	public static final int SAFI_MULTICAST = 2;
	public static final int SAFI_UNICAST_MULTICAST = 3;
	public static final int BGPDUMP_MAX_SAFI = SAFI_UNICAST_MULTICAST;
	
	public static final int MAX_PREFIXES = 1000;
	
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

	/* NLRI */
/*
	public class Prefix{
		public int prefix_len;
		public String prefix;
	}
*/	
	public class Mp_info{
		public Mp_NLRI	withdraw[][] = new Mp_NLRI[BGPDUMP_MAX_AFI+1][BGPDUMP_MAX_SAFI+1];;
		public Mp_NLRI	announce[][] = new Mp_NLRI[BGPDUMP_MAX_AFI+1][BGPDUMP_MAX_SAFI+1];;
	}
	
	public class Mp_NLRI {
		public int		nexthop_len;
		public String	nexthop;
		public String 	nexthop_local;
		public int		prefix_count;
		public ArrayList<Prefix> prefixs = new ArrayList<Prefix>();;
	}
		
	public class Unknown_attr
	{
		public int	flag;
		public int	type;
		public int	len;
		public int raw;
	}
	
	public class Aspath 
	{
		public int	asn_len;
		public int 	length;
		public int 	count;
		public StringBuilder aspaths = new StringBuilder();		
	};
	
	public int flag;
	public int origin;
	public String nexthop;
	public int med;
	public int local_pref;
	public long aggregator_as;
	public String aggregator_addr;
	public int weight;
	public String originator_id;

	public Aspath aspaths;
	public ArrayList<String> clusters;
	public StringBuilder communites;
	public ArrayList<String> ecommunities;
	int transit_len;
	int transit_val;
	
	public Mp_info mp_info;
	public String data;
	public int unknown_num;
	public Unknown_attr unknown;
	
	  /* ASN32 support */
	public Aspath new_aspath;
	public Aspath old_aspath;
	public long new_aggregator_as;
	public long old_aggregator_as;
	public String new_aggregator_addr;
	public String old_aggregator_addr;
	
	public Bgp4mp_Attributes() {
		super();
		// TODO Auto-generated constructor stub		
		aspaths = new Aspath();
		clusters = new ArrayList<String>();
		communites = new StringBuilder();
		ecommunities = new ArrayList<String>();
		
		mp_info = new Mp_info();
		new_aspath = new Aspath();
		old_aspath = new Aspath();
	}

	private Mp_NLRI get_nexthop(EZBytes eb, int pos, int afi) throws UnknownHostException {
	    
		Mp_NLRI nlri = new Mp_NLRI();
		nlri.nexthop_len = BinaryUtils.byteToInt(eb.GetBytes(pos,1)); pos++;

	    if(afi == AFI_IP && nlri.nexthop_len == 4) {
			nlri.nexthop = InetAddress.getByAddress(eb.GetBytes(pos, 4)).toString().substring(1); pos+=4;
	    	return nlri;
	    }else if(nlri.nexthop_len != 32) {
			nlri.nexthop = Inet6Address.getByAddress(eb.GetBytes(pos, 16)).toString().substring(1); pos+=32;
	    }else if(nlri.nexthop_len != 16) {
//            warn("process_mp_announce: unknown MP nexthop length %d", nlri.nexthop_len);
	    }
	    return nlri;
	}
	
	int read_prefix_list(EZBytes eb, int afi, ArrayList<Prefix> prefixs, Incomplete incomplete, int len) throws UnknownHostException {
	    int count = 0;
	    int p_len = 0;
	    int p_bytes = 0;
        byte[] bprefix = new byte[4];
        int pos = 0;
        
//	    EZBytes eb = new EZBytes(len);
//	    eb.PutBytes(pdata,0,eb.getLength());
	    
	    while(pos<eb.getLength()) {
	        p_len = BinaryUtils.byteToInt(eb.GetBytes(pos,1)); pos++;
	        p_bytes = (p_len + 7) / 8;
	        
	        if(p_len==0) return count;
	        
	        /* Truncated prefix list? */
	        if(eb.getLength()-pos < p_bytes) {
	        	
	            if(incomplete == null)	break;
	            
	            incomplete.afi = afi;
	            incomplete.orig_len = p_len;
	            incomplete.prefix.prefix_len = (eb.getLength()-pos) * 8;
	            
	            if(eb.getLength()-pos >= p_bytes){
	            	if(incomplete.prefix!=null){
		    	        System.arraycopy(eb.GetBytes(pos, eb.getLength()-pos), 0, bprefix, 0, eb.getLength()-pos);
		            	incomplete.prefix.prefix = InetAddress.getByAddress(bprefix).toString().substring(1); pos=eb.getLength(); 
	            	}else{}
	            }
	            break;
	        }
	        
	        if(afi==AFI_IP){
	        	if(p_bytes > 4) return count;
	        	bprefix = new byte[4];
	        	System.arraycopy(eb.GetBytes(pos, p_bytes), 0, bprefix, 0, p_bytes);
	        	prefixs.add(new Prefix(p_len, InetAddress.getByAddress(bprefix).toString().substring(1)));	 
	        	
	        }else if(afi==AFI_IP6){
	        	if(1==1) return 100;
	        	if(p_bytes > 16) return count;
	        	bprefix = new byte[16];
	        	System.arraycopy(eb.GetBytes(pos, p_bytes), 0, bprefix, 0, p_bytes);
	        	prefixs.add(new Prefix(p_len, Inet6Address.getByAddress(bprefix).toString().substring(1)));	
	        }
      
	        pos+=p_bytes; 
	        if(count++ > MAX_PREFIXES)	continue;
	    }	    
	    if(count > MAX_PREFIXES) {
	        return MAX_PREFIXES;
	    }	    
	    return count;
	}
			
	private boolean process_mp_announce(EZBytes eb, Incomplete incomplete) throws UnknownHostException{
		int pos = 0;
	    int afi = BinaryUtils.byteToInt(eb.GetBytes(pos, 2)); pos+=2;
	    int safi = BinaryUtils.byteToInt(eb.GetBytes(pos, 1)); pos+=1;	            
	    if(afi > BGPDUMP_MAX_AFI || safi > BGPDUMP_MAX_SAFI) return false;
	    
	    if(mp_info.announce[afi][safi] != null)  return false;

	    mp_info.announce[afi][safi] = get_nexthop(eb, pos, afi);

	    int num_snpa = BinaryUtils.byteToInt(eb.GetBytes(pos, 1)); pos++;
	    pos+=num_snpa;
	    int len = eb.getLength()-pos;
	    EZBytes new_eb = new EZBytes(len);
		new_eb.PutBytes(eb.GetBytes(pos, len), 0, len);
	    mp_info.announce[afi][safi].prefix_count = read_prefix_list(new_eb, afi, mp_info.announce[afi][safi].prefixs, incomplete, len);
	    
		return true;	    
	}
	
	private boolean process_mp_withdraw(EZBytes eb, Incomplete incomplete) throws UnknownHostException {
		int pos = 0;
	    int afi = BinaryUtils.byteToInt(eb.GetBytes(pos, 2)); pos+=2;
	    int safi = BinaryUtils.byteToInt(eb.GetBytes(pos, 1)); pos+=1;	    
		/* Do we know about this address family? */
		if(afi > BGPDUMP_MAX_AFI || safi > BGPDUMP_MAX_SAFI)	return false;

		/* If there are 2 NLRI's for the same protocol, fail but don't burn and die */
		if(mp_info.withdraw[afi][safi] != null)	return false;

		mp_info.withdraw[afi][safi] = new Mp_NLRI();
	    int len = eb.getLength()-pos;
	    EZBytes new_eb = new EZBytes(len);
		new_eb.PutBytes(eb.GetBytes(pos, len), 0, len);
		mp_info.withdraw[afi][safi].prefix_count = read_prefix_list(new_eb, afi, mp_info.withdraw[afi][safi].prefixs, incomplete, len);
		return true;
	}

	private char aspath_delimiter_char (int type, int which) {
		  
		  class Aspath_delim_char
		  {
		    int type;
		    char start;
		    char end;		    
			public Aspath_delim_char(int type, char start, char end) {
				super();
				this.type = type;
				this.start = start;
				this.end = end;
			}		    
		  }
		  
		  Aspath_delim_char[] delim = new Aspath_delim_char[5];
		  delim[0] = new Aspath_delim_char(AS_SET, '{', '}');		  
		  delim[1] = new Aspath_delim_char(AS_SEQUENCE, ' ', ' ');
		  delim[2] = new Aspath_delim_char(AS_CONFED_SET, '[', ']');
		  delim[3] = new Aspath_delim_char(AS_CONFED_SEQUENCE, '(', ')');
		  delim[4] = new Aspath_delim_char(0, '\0', '\0' );

		  for (int i = 0; delim[i].type != 0; i++){
		      if (delim[i].type == type){
		    	  if (which == AS_SEG_START)
		    		  return delim[i].start;
		    	  else if (which == AS_SEG_END)
		    		  return delim[i].end;
		      }
		  }
		  return ' ';
	}
	
	void process_attr_aspath_string(EZBytes eb, Aspath aspaths) {
		
		int MAX_ASPATH_LEN = 8000; 
		final int ASN16_LEN = 2;
		final int ASN32_LEN = 4;
		
	    boolean space = false;
	    int type = AS_SEQUENCE;
	    int pos = 0;
	    
	    int segment_type = 0;
	    int segment_len = 0;
	    
	    while(pos < eb.getLength()){
			segment_type = BinaryUtils.byteToInt(eb.GetBytes(pos,1)); pos++;
			segment_len = BinaryUtils.byteToInt(eb.GetBytes(pos,1)); pos++;
			
			if (type != AS_SET &&  type != AS_SEQUENCE && type != AS_CONFED_SET && type != AS_CONFED_SEQUENCE)
				return;
//			if ((pos + segment_len * aspaths.asn_len + AS_HEADER_SIZE) > eb.getLength())
			if ((pos + segment_len * aspaths.asn_len) > eb.getLength())
				return;
	
			if (type != AS_SEQUENCE)
				aspaths.aspaths.append(aspath_delimiter_char(type, AS_SEG_END));
			if (space)
				aspaths.aspaths.append(' ');
	
			if (segment_type != AS_SEQUENCE)
				aspaths.aspaths.append(aspath_delimiter_char (segment_type, AS_SEG_START));
	
			space = false;
	
			switch(segment_type){
			case AS_SEQUENCE:
			case AS_CONFED_SEQUENCE:
				aspaths.count += segment_len;
				break;
			case AS_SET:
			case AS_CONFED_SET:
				aspaths.count += 1;
				break;
			}
	
//			for (; pos < segment_len; pos+=aspaths.asn_len){
			for (int i=0; i < segment_len; i++, pos+=aspaths.asn_len){
			  long asn = 0;
	
			  if (space){
			      if (segment_type == AS_SET || segment_type == AS_CONFED_SET)
			    	  aspaths.aspaths.append(',');
			      else
			    	  aspaths.aspaths.append(' ');
			  }else
				  space = true;
	
	          switch(aspaths.asn_len) {
	                case ASN16_LEN:
	                    asn = BinaryUtils.byteToInt(eb.GetBytes(pos,2));
	                    break;
	                case ASN32_LEN:
	                    asn = BinaryUtils.byteToInt(eb.GetBytes(pos,4));
	                    break;
	                default:
	          }
	          if(asn!=0) 
	        	  aspaths.aspaths.append(asn);
	          if(pos > MAX_ASPATH_LEN - 100) {
	              aspaths.aspaths.append("...");
	              return;
	          }
			}
			type = segment_type;
		}

	    if (segment_type != AS_SEQUENCE)
		  aspaths.aspaths.append(aspath_delimiter_char (segment_type, AS_SEG_END));
	}


	void process_attr_community_string(EZBytes eb, StringBuilder communities) {
	
		for (int pos=0; pos<eb.getLength(); pos+=4){
			int comval = BinaryUtils.byteToInt(eb.GetBytes(pos, 4)); //pos+=4;
			switch (comval){
			case COMMUNITY_NO_EXPORT:
				communities.append(" no-export");
				break;
			case COMMUNITY_NO_ADVERTISE:
				communities.append(" no-advertise");
				break;
			case COMMUNITY_LOCAL_AS:
				communities.append(" local-AS");
				break;
			default:				
				int as = (comval >> 16) & 0xFFFF;
				int val = comval & 0xFFFF;
				communities.append(" ").append(as+":"+val);
				break;
			}
	    }
	}
	
	private void process_unknown_attr(int flag, int type, int len){
//		pos+=len;
	}
	
	private int parseOneAttribute(EZBytes eb, int pos, Incomplete incomplete, int asn_len) throws UnknownHostException{
		int flag = BinaryUtils.byteToInt(eb.GetBytes(pos,1)); pos++;
		int type = BinaryUtils.byteToInt(eb.GetBytes(pos,1)); pos++;
		int len = 0;
		
		if((flag&BGP_ATTR_FLAG_EXTLEN) == BGP_ATTR_FLAG_EXTLEN){
			len = BinaryUtils.byteToInt(eb.GetBytes(pos,2)); pos+=2;
		}else{
			len = BinaryUtils.byteToInt(eb.GetBytes(pos,1)); pos+=1;
		}
		
		if(len > eb.getLength()-pos || len == 0) return eb.getLength();
		
		EZBytes new_eb = new EZBytes(len);
		new_eb.PutBytes(eb.GetBytes(pos, len), 0, len);
		
	    if(type <= 4*8)
	    	this.flag |= (1 << ((type) - 1));
	        
        switch(type){
        case BGP_ATTR_MP_REACH_NLRI:
            process_mp_announce(new_eb, incomplete); //pos+=len;
            break;
        case BGP_ATTR_MP_UNREACH_NLRI:
            process_mp_withdraw(new_eb, incomplete); //pos+=len;
            break;
        case BGP_ATTR_ORIGIN:
            origin = BinaryUtils.byteToInt(eb.GetBytes(pos,1)); //pos+=1;
            break;
        case BGP_ATTR_AS_PATH:
        	aspaths.asn_len = asn_len;
            process_attr_aspath_string(new_eb, aspaths); // pos+=len;
            break;
        case BGP_ATTR_NEXT_HOP:
            nexthop = InetAddress.getByAddress(eb.GetBytes(pos, 4)).toString().substring(1); //pos+=4;
            break;
        case BGP_ATTR_MULTI_EXIT_DISC:
        	med = BinaryUtils.byteToInt(eb.GetBytes(pos, 4)); //pos+=4;
            break;
        case BGP_ATTR_LOCAL_PREF:
        	local_pref = BinaryUtils.byteToInt(eb.GetBytes(pos, 4)); //pos+=4;
            break;
        case BGP_ATTR_ATOMIC_AGGREGATE:
            break;
        case BGP_ATTR_AGGREGATOR:
            new_aggregator_as = BinaryUtils.ubyteToLong(eb.GetBytes(pos, asn_len)); //pos+=asn_len;
            aggregator_addr = InetAddress.getByAddress(eb.GetBytes(pos+asn_len, 4)).toString().substring(1); //pos+=4;
            break;
        case BGP_ATTR_COMMUNITIES:
            process_attr_community_string(new_eb, communites); //pos+=len;
            break;
        case BGP_ATTR_NEW_AS_PATH:
            process_attr_aspath_string(new_eb, aspaths); //pos+=len;
//            check_new_aspath(new_aspath);
            break;
        case BGP_ATTR_NEW_AGGREGATOR:
            new_aggregator_as = BinaryUtils.ubyteToLong(eb.GetBytes(pos, 4)); //pos+=4;
            new_aggregator_addr = InetAddress.getByAddress(eb.GetBytes(pos+4, 4)).toString().substring(1); //pos+=4;
            break;
        case BGP_ATTR_ORIGINATOR_ID:
        	originator_id = InetAddress.getByAddress(eb.GetBytes(pos, 4)).toString().substring(1);// pos+=4;
            break;
        case BGP_ATTR_CLUSTER_LIST:
            int length = len/4;
            for (int i = 0; i < length; i++)
                clusters.add(InetAddress.getByAddress(eb.GetBytes(pos, 4)).toString().substring(1)); //pos+=4;
            break;
        default:
            process_unknown_attr(flag, type, len); //pos+=len;
	    }
        pos+=len;
		return pos; 
	}
	
	public boolean parseAttributes(EZBytes eb, Incomplete incomplete, int asn_len) throws UnknownHostException{	
		int pos = 0;
//		EZBytes new_eb = new EZBytes(total);
//		new_eb.PutBytes(eb.GetBytes(pos, total), 0, total); pos+=total;
//		int new_pos = 0;
		while(eb.getLength()-pos > 0){
			pos=parseOneAttribute(eb, pos, incomplete, asn_len);			
		}
		return true;
	}
	
	String getPrefix_fromMP_info(){
		
		StringBuilder sb = new StringBuilder();

		if(mp_info.announce[AFI_IP][SAFI_UNICAST] != null && mp_info.announce[AFI_IP][SAFI_UNICAST].prefix_count > 0){
			sb.append("announceCnt: "+mp_info.announce[AFI_IP][SAFI_UNICAST].prefix_count).append("|");
			for(Prefix prefix : mp_info.announce[AFI_IP][SAFI_UNICAST].prefixs)
				sb.append(prefix.prefix+"/"+prefix.prefix_len).append("|");
					
		}else if(mp_info.announce[AFI_IP][SAFI_MULTICAST] != null && mp_info.announce[AFI_IP][SAFI_MULTICAST].prefix_count > 0){
			sb.append("announceCnt: "+mp_info.announce[AFI_IP][SAFI_UNICAST].prefix_count).append("|");
			for(Prefix prefix : mp_info.announce[AFI_IP][SAFI_MULTICAST].prefixs)
				sb.append(prefix.prefix+"/"+prefix.prefix_len).append("|");
					
		}else if(mp_info.announce[AFI_IP][SAFI_UNICAST_MULTICAST] != null && mp_info.announce[AFI_IP][SAFI_UNICAST_MULTICAST].prefix_count > 0){
			sb.append("announceCnt: "+mp_info.announce[AFI_IP][SAFI_UNICAST_MULTICAST].prefix_count).append("|");
			for(Prefix prefix : mp_info.announce[AFI_IP][SAFI_UNICAST_MULTICAST].prefixs)
				sb.append(prefix.prefix+"/"+prefix.prefix_len).append("|");
					
		}else if(mp_info.announce[AFI_IP6][SAFI_UNICAST] != null && mp_info.announce[AFI_IP6][SAFI_UNICAST].prefix_count > 0){
			sb.append("announceCnt: "+mp_info.announce[AFI_IP6][SAFI_UNICAST].prefix_count).append("|");
			for(Prefix prefix : mp_info.announce[AFI_IP6][SAFI_UNICAST].prefixs)
				sb.append(prefix.prefix+"/"+prefix.prefix_len).append("|");
					
		}else if(mp_info.announce[AFI_IP6][SAFI_MULTICAST] != null && mp_info.announce[AFI_IP6][SAFI_MULTICAST].prefix_count > 0){
			sb.append("announceCnt: "+mp_info.announce[AFI_IP6][SAFI_MULTICAST].prefix_count).append("|");
			for(Prefix prefix : mp_info.announce[AFI_IP6][SAFI_MULTICAST].prefixs)
				sb.append(prefix.prefix+"/"+prefix.prefix_len).append("|");
					
		}else if(mp_info.announce[AFI_IP6][SAFI_UNICAST_MULTICAST] != null && mp_info.announce[AFI_IP6][SAFI_UNICAST_MULTICAST].prefix_count > 0){
			sb.append("announceCnt: "+mp_info.announce[AFI_IP6][SAFI_UNICAST_MULTICAST].prefix_count).append("|");
			for(Prefix prefix : mp_info.announce[AFI_IP6][SAFI_UNICAST_MULTICAST].prefixs)
				sb.append(prefix.prefix+"/"+prefix.prefix_len).append("|");
		}else {
			sb
			.append("announceCnt: 0")
			.append("|")
			.append("|");
		}

		return sb.toString();
	}
	
	public String getNexthop_fromMP_info(){
//		String nexthop;
		if(mp_info.announce[AFI_IP6][SAFI_UNICAST] != null && mp_info.announce[AFI_IP6][SAFI_UNICAST].nexthop != null)
			return mp_info.announce[AFI_IP6][SAFI_UNICAST].nexthop +"///"+ mp_info.announce[AFI_IP6][SAFI_UNICAST].prefixs.size();
		
		else if(mp_info.announce[AFI_IP6][SAFI_MULTICAST] != null && mp_info.announce[AFI_IP6][SAFI_MULTICAST].nexthop != null)
			return mp_info.announce[AFI_IP6][SAFI_MULTICAST].nexthop;
		
		else if(mp_info.announce[AFI_IP6][SAFI_UNICAST_MULTICAST] != null && mp_info.announce[AFI_IP6][SAFI_UNICAST_MULTICAST].nexthop != null)
			return mp_info.announce[AFI_IP6][SAFI_UNICAST_MULTICAST].nexthop;
		
		return null;
	}
	
	public String toString(){
		StringBuilder sb = new StringBuilder();
		sb
		.append("flag:"+flag).append("|")
		.append("origin:"+origin).append("|");
		if(nexthop!=null)
			sb.append("nexthop:"+nexthop).append("|");
		else 
			sb.append("nexthop:"+getNexthop_fromMP_info()).append("|");
		
		sb
		.append("med:"+med).append("|")
		.append("local_pref:"+local_pref).append("|")
		.append("aggregator_as:"+aggregator_as).append("|")
		.append("aggregator_addr:"+aggregator_addr).append("|")
		.append("weight:"+weight).append("|")
		.append("originator_id:"+originator_id).append("|")
		.append("aspaths:"+aspaths.aspaths).append("|")
		.append("community:"+communites);
		
		return sb.toString();
	}
}

