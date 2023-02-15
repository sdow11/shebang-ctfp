import sys

#Purpose: To find common exploitable commands we saw in projects in C files
#Idea: If file contains command exploitable commands, this script provides the line and line number of the command
#Covers buffer overflow commands and execution commands




def analyzeFile(filepath):
	commands = ["strcpy", "gets", "stpcpy", "strcat", "strcmp", "sprintf", "printf", "vsprintf", "system", "system", "execl", "execlp" , "execvp", "scanf", "sscanf", "fscanf"]
	prog = open(filepath, 'r')
	linenum = 1
	for line in prog:
		for c in commands:
			if c in line:
				print("Line {}: Contains {} in Line {}\n".format(line.replace('\t', ''),c, linenum))
		linenum +=1
				
				
				
				
				
if __name__ == "__main__":
	if len(sys.argv) < 2:
		print("Provide path of file to scan")
		exit(1)
	path = sys.argv[1]
	if ".c" in path:
		analyzeFile(path)
