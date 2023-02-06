string = input("")
val = 4

matrix = [['' for j in range(len(string))] for i in range(val)]

#encryption
row = 0
col = 0
encrypted_string = ""
pos = 1
for i in range(len(string)):
	if row == val:
		row -= 2
		pos = -1
	elif row == -1:
		row += 2
		pos = 1
	
	matrix[row][col] = string[i]
	row += (1 *pos)
	col += 1

for i in range(val):
	for j in range(len(string)):
		if matrix[i][j] != '':
			encrypted_string += matrix[i][j]

print(encrypted_string)
