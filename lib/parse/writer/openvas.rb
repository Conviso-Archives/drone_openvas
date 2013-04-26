
module Parse
  module WRITER
    class Arachni
    @@file=0

     def initialize(x)
     if File.exist?(x)
      @@file=x
      fd=File.new(x)
      doc = Document.new fd
      @@rows=doc.root
     else
      @ret= "Error in Load File!"
     end 
    end

   def write_xml(hash)
    doc = Document.new
    doc.add_element("scan")
    doc.root.add_element("header")
    header = doc.root.elements[1]
    header.add_element("tool")
    header.elements["tool"].text = hash[:toolname]
    header.add_element("project")
    header.elements["project"].text = "nome projeto cadastro checker"
    header.add_element("timestamp")
    header.elements["timestamp"].text = hash[:scan_start]
    header.add_element("duration")
    header.elements["duration"].text = hash[:scan_end]
   #vulnerabilidades
    start = Element.new("vulnerabilities")
    hash[:results].each do |x|
     vuln = doc.root.elements[1]
     vuln = Element.new("vulnerability")
# para pegar valores do description e dividir em solution e reference e description
     text_description=[]
     text_description=str.split(/\n\n/,5)
#fazendo o xml
     vuln.add_attribute("id", x["hash"])
     vuln.add_element("title")
     vuln.elements["title"].text=x["name"]
     vuln.add_element("description")
     vuln.elements["description"].text=text_description[1]
     vuln.add_element("category")
     vuln.elements["category"].text=x["family"]
     vuln.add_element("impact")
     vuln.elements["impact"].text=x["original_threat"]
     vuln.add_element("exploitability")
     vuln.elements["exploitability"].text=x["original_threat"]
     vuln.add_element("reproduction")
     vuln.elements["reproduction"].text=x["cve"]
     vuln.add_element("control")
     vuln.elements["control"].text=text_description[2]
     vuln.add_element("reference")
     vuln.elements["reference"].text=text_description[2]
   
     start << vuln
    end
 
    doc.root.insert_after("//header",start)

    File.open(@@file, "w") do |file| 
     file.puts doc
    end 
   end


    end
  end
end
