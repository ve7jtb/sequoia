package dev.hybridmail;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import com.google.gson.*;
/** Generates public SOFTWARE-only interop vectors; no token or private-key export. */
public final class GenerateRestoreFixture {
 public static void main(String[] args)throws Exception {
  MailEngine.init();
  var ids=Identity.generateSoftwareProfile("restore@example.test",TokenProfile.LEVEL3,List.of("alias@example.test"));
  var id=ids.get(1);var hw=new Rfc9980Test.Hardware(id);
  var certId=Identity.generateSoftwareProfile("cert@example.test",TokenProfile.LEVEL3,List.of()).get(1);
  var certHw=new Rfc9980Test.Hardware(certId);
  Map<String,PublicKey> keys=new TreeMap<>();
  keys.put("9c",OpenPgp.identityKeys(id,true).pq());keys.put("9d",OpenPgp.identityKeys(id,false).pq());
  keys.put("83",OpenPgp.identityKeys(id,true).ec());keys.put("82",OpenPgp.identityKeys(id,false).ec());
  keys.put("84",hw.ed.getPublic());keys.put("85",hw.x.getPublic());
  keys.put("86",OpenPgp.identityKeys(certId,true).pq());keys.put("87",certHw.ed.getPublic());
  keys.put("88",hw.compatEd.getPublic());keys.put("89",hw.compatX.getPublic());
  Path root=Files.createTempDirectory("restore-fixture-");
  try {
   var legacy=OpenPgp.createRfc9980(id,hw,hw.ed.getPublic(),hw.x.getPublic());
   var own=Level3OpenPgpSetup.issue(root,root.resolve("setup"),id,keys,hw,certHw);
   var entries=List.of(new CertificateBundle.Entry(ids.get(0),123456,"9c","83","9d","82"),new CertificateBundle.Entry(id,123456,"9c","83","9d","82"));
   var profiles=OnKeyBundle.collect(entries,root);
   var output=new JsonObject();output.addProperty("serial",123456);output.addProperty("fingerprint",own.fingerprint());
   var publicKeys=new JsonObject();for(var e:keys.entrySet())publicKeys.addProperty(e.getKey(),Base64.getEncoder().encodeToString(e.getValue().getEncoded()));output.add("keys",publicKeys);
   // Both real BC signature encodings are independently exercised by Rust.
   output.addProperty("pure",Base64.getEncoder().encodeToString(OnKeyStorage.pack(OnKeyBundle.sign(profiles,0,hw))));
   output.addProperty("hybrid",Base64.getEncoder().encodeToString(OnKeyStorage.pack(OnKeyBundle.sign(profiles,1,hw))));
   var legacyProfiles=List.of(new OnKeyBundle.Profile(entries.get(0),new byte[0]),new OnKeyBundle.Profile(entries.get(1),legacy.encoded));
   output.addProperty("legacy",Base64.getEncoder().encodeToString(OnKeyBundle.sign(legacyProfiles,1,hw)));
   Files.writeString(Path.of(args[0]),new GsonBuilder().setPrettyPrinting().create().toJson(output));
  } finally {try(var files=Files.walk(root)){for(Path p:files.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
 }
}
