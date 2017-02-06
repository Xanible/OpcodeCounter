package opcodecounter;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class Main {

	public static void main(String[] args) {

		List<String> opcodes = new ArrayList<String>();
		HashMap<String, Integer> malOpcodes = new HashMap<String, Integer>();
		HashMap<String, Integer> benOpcodes = new HashMap<String, Integer>();
		File malDir = new File("C:\\Users\\ColbyAdmin\\Desktop\\Test\\Malware");
		File benDir = new File("C:\\Users\\ColbyAdmin\\Desktop\\Test\\Benign");
		File[] malFiles = malDir.listFiles();
		File[] benFiles = benDir.listFiles();
		
		

		// Loop through Malware
		for(File f: malFiles) {
			try {
				BufferedReader br = new BufferedReader(new FileReader(f));
				for (String line = br.readLine(); line != null; line = br.readLine()) {
					if(!opcodes.contains(line)) {
						opcodes.add(line);
					}
					if(malOpcodes.containsKey(line)) {
						int currentVal = malOpcodes.get(line);
						currentVal++;
						malOpcodes.put(line, currentVal);
					} else {
						malOpcodes.put(line, 1);
					}
				}
				br.close();
			} catch (FileNotFoundException e) {
				System.out.println("Error opening file: " + f.getAbsolutePath());
			} catch (IOException e) {
				System.out.println("Error reading from file: " + f.getAbsolutePath());
			}
		}

		// Loop through Benign
		for(File f: benFiles) {
			try {
				BufferedReader br = new BufferedReader(new FileReader(f));
				for (String line = br.readLine(); line != null; line = br.readLine()) {
					if(!opcodes.contains(line)) {
						opcodes.add(line);
					}
					if(benOpcodes.containsKey(line)) {
						int currentVal = benOpcodes.get(line);
						currentVal++;
						benOpcodes.put(line, currentVal);
					} else {
						benOpcodes.put(line, 1);
					} 
				}
				br.close();
			} catch (FileNotFoundException e) {
				System.out.println("Error opening file: " + f.getAbsolutePath());
			} catch (IOException e) {
				System.out.println("Error reading from file: " + f.getAbsolutePath());
			}
		}
		
		// Output results
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter("C:\\Users\\ColbyAdmin\\Desktop\\Test\\results.txt"));
			for(String s : opcodes) {
				bw.write(s);
				bw.write(" ");
				if(malOpcodes.containsKey(s)){
					bw.write(String.valueOf(malOpcodes.get(s)));
					bw.write(" ");
				} else {
					bw.write(String.valueOf(0));
					bw.write(" ");
				}
				if(benOpcodes.containsKey(s)){
					bw.write(String.valueOf(benOpcodes.get(s)));
					bw.newLine();;
				} else {
					bw.write(String.valueOf(0));
					bw.newLine();
				}
			}
			bw.close();
		} catch (IOException e) {
			System.out.println("Error writing to source file.");
		}
	}
}