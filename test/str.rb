str="Description :

  The remote version of this software is vulnerable to multiple SQL
  injection attacks due to its failure to properly sanitize certain
  parameters.  Provided PHP's 'magic_quotes_gpc' setting is disabled,
  these flaws allow an attacker to manipulate database queries, which
  may result in the disclosure or modification of data.

  See also:
  http://securityfocus.org/archive/1/411909
  http://archives.neohapsis.com/archives/secunia/2005-q4/0021.html

  Solution:
  Update to at least version 6.00.110 of PHP-Fusion."


puts str
array=[]
array=str.split(/\n\n/,5)
puts array.inspect

puts "teste----------------"
puts array[1]
puts "teste2--------"
puts array[2]
puts "teste3----------"
puts array[3]

