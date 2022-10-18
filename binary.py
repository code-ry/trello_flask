def decimal_to_binary (decimal):
	binary = ''
	while decimal > 0:
		binary_digit = (decimal % 2)
		binary += str(binary_digit)
		decimal = int(decimal/2)
print 				
