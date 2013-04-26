require "rexml/document"

output={}
output[:results]=[]

 fd = File.new( "sample/report-0f015c6e-5de7-4eab-8e9a-3113a92e262f.xml" )
 doc = REXML::Document.new fd
 rows=doc.root

 #puts rows.elements['//report/results/result']
#puts rows.elements['//report/results/result']

puts rows.elements['//report/scan_start']
puts rows.elements['//report/scan_end']

 path='//report/results/result'
 output[:results] = rows.elements.collect(path) do |row| 
 {
  :hash => row.attributes['id'],
  :name => row.elements['nvt/name'].text.to_s,
  :cve => row.elements['nvt/cve'].text.to_s
 }
 end

 puts output.inspect
