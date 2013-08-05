package bgpdoop.hadoop.mapreduce.lib.output;

import java.io.IOException;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.SequenceFile.CompressionType;
import org.apache.hadoop.io.compress.CompressionCodec;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.Reporter;
import org.apache.hadoop.mapreduce.RecordWriter;
import org.apache.hadoop.mapreduce.TaskAttemptContext;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;
import org.apache.hadoop.util.Progressable;

/** An {@link OutputFormat} that writes {@link SequenceFile}s. */
public class BinaryOutputFormat <K,V> extends FileOutputFormat<K, V> {

	@Override
	public RecordWriter<K, V> getRecordWriter(TaskAttemptContext context)
			throws IOException, InterruptedException {
		// TODO Auto-generated method stub
	    Configuration conf = context.getConfiguration();
	    // get the path of the temporary output file 
	    Path file = getDefaultWorkFile(context, "");
	    FileSystem fs = file.getFileSystem(conf);

	    final FSDataOutputStream fileOut = fs.create(file);

	    return new RecordWriter<K, V>() {
	        
	        public void write(Object key, Object value)
	          throws IOException {
	        	if(key instanceof BytesWritable){
	        		BytesWritable bkey = (BytesWritable)key;
	        		fileOut.write(bkey.getBytes(), 0, bkey.getLength());
	        	}
	        	if(value instanceof BytesWritable){
	        		BytesWritable bvalue = (BytesWritable)value;
	        		fileOut.write(bvalue.getBytes(), 0, bvalue.getLength());
	        	}        	
	        }

	        public void close(TaskAttemptContext context) throws IOException { 
	        	fileOut.close();
	        }
	      };
	}
}
