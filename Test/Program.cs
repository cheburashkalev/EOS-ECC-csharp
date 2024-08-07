// See https://aka.ms/new-console-template for more information
using eos_ecc;
var data = "";
var pvt_key = "";
var pub_key = "";
var sign = ApiCommon.SignData(data, pvt_key);
var res = ApiCommon.VerifySignature(sign, data, pub_key);
Console.WriteLine("Hello, World!");
