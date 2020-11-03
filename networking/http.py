# decodes HTTP data

class HTTP:
    def __init__(self, raw_data):
        try:
            # Decodes the data into 'utf-8' character set
            self.data = raw_data.decode('utf-8')
        except:
            self.data = raw_data