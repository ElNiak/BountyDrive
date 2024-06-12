# Setup logging
import datetime
import sys

today_date = datetime.now().strftime("%Y-%m-%d")
orig_stdout = sys.stderr
f = open(f'logs/{today_date}.log', 'w')
class Unbuffered:
    def __init__(self, stream):
       self.stream = stream
    
    def flush(self):
        pass

    def write(self, data):
       self.stream.write(data)
       self.stream.flush()
       f.write(data)    # Write the data of stdout here to a text file as well

sys.stderr = Unbuffered(sys.stderr)