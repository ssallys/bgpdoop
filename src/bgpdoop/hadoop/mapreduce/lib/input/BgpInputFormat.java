package bgpdoop.hadoop.mapreduce.lib.input;

import java.io.IOException;

import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.compress.CompressionCodec;
import org.apache.hadoop.io.compress.CompressionCodecFactory;
import org.apache.hadoop.mapreduce.InputFormat;
import org.apache.hadoop.mapreduce.InputSplit;
import org.apache.hadoop.mapreduce.JobContext;
import org.apache.hadoop.mapreduce.RecordReader;
import org.apache.hadoop.mapreduce.TaskAttemptContext;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;

public class BgpInputFormat extends FileInputFormat<LongWritable,BytesWritable>{

	  public RecordReader<LongWritable,BytesWritable> createRecordReader(InputSplit genericSplit, 
			  TaskAttemptContext context){
	    return new BgpVlenRecordReader();
	  }
	  
	  protected boolean isSplitable(JobContext context, Path file) {
		    CompressionCodec codec = 
		  	      new CompressionCodecFactory(context.getConfiguration()).getCodec(file);
		  	    return codec == null;
	  }
}