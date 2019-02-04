//
//  ViewController.swift
//  stringencryptdecrypt
//
//  Created by admin on 21/01/19.
//  Copyright © 2019 professional. All rights reserved.
//

import UIKit
import RNCryptor
import CryptoSwift

class ViewController: UIViewController {
    
    //encrypt
    @IBOutlet weak var keyencrypt: UITextField!
    
    @IBOutlet weak var stringencrypt: UITextField!
    
    @IBOutlet weak var outputencrypt: UITextField!
    

    //decrypt
    
    @IBOutlet weak var keydecrypt: UITextField!
    
    @IBOutlet weak var stringdecrypt: UITextField!
    
    
    @IBOutlet weak var outputdecrypt: UITextField!
    
    
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
    }

// encrypt
    @IBAction func encryptbutton(_ sender: Any) {
        let input = stringencrypt.text
        let key = keyencrypt.text
        let iv = "gqLOHUioQ0QjhuvI"
        let encryp = try! input!.aesEncrypt(key: key!, iv: iv)
        outputencrypt.text = encryp
        
    }
    
//decrypt
    
    @IBAction func decryptbutton(_ sender: Any) {
        let input = stringdecrypt.text
        let key = keydecrypt.text
        let iv = "gqLOHUioQ0QjhuvI"
        let decrypt = try! input!.aesDecrypt(key: key!, iv: iv)
         outputdecrypt.text = decrypt
    }
    
    
}

extension String {
    
    func aesEncrypt(key:String, iv:String, options:Int = kCCOptionPKCS7Padding) -> String? {
        if let keyData = key.data(using: String.Encoding.utf8),
            let data = self.data(using: String.Encoding.utf8),
            let cryptData    = NSMutableData(length: Int((data.count)) + kCCBlockSizeAES128) {
            
            
            let keyLength              = size_t(kCCKeySizeAES128)
            let operation: CCOperation = UInt32(kCCEncrypt)
            let algoritm:  CCAlgorithm = UInt32(kCCAlgorithmAES128)
            let options:   CCOptions   = UInt32(options)
            
            
            
            var numBytesEncrypted :size_t = 0
            
            let cryptStatus = CCCrypt(operation,
                                      algoritm,
                                      options,
                                      (keyData as NSData).bytes, keyLength,
                                      iv,
                                      (data as NSData).bytes, data.count,
                                      cryptData.mutableBytes, cryptData.length,
                                      &numBytesEncrypted)
            
            if UInt32(cryptStatus) == UInt32(kCCSuccess) {
                cryptData.length = Int(numBytesEncrypted)
                let base64cryptString = cryptData.base64EncodedString(options: .lineLength64Characters)
                return base64cryptString
                
                
            }
            else {
                return nil
            }
        }
        return nil
    }
    
    func aesDecrypt(key:String, iv:String, options:Int = kCCOptionPKCS7Padding) -> String? {
        if let keyData = key.data(using: String.Encoding.utf8),
            let data = NSData(base64Encoded: self, options: .ignoreUnknownCharacters),
            let cryptData    = NSMutableData(length: Int((data.length)) + kCCBlockSizeAES128) {
            
            let keyLength              = size_t(kCCKeySizeAES128)
            let operation: CCOperation = UInt32(kCCDecrypt)
            let algoritm:  CCAlgorithm = UInt32(kCCAlgorithmAES128)
            let options:   CCOptions   = UInt32(options)
            
            var numBytesEncrypted :size_t = 0
            
            let cryptStatus = CCCrypt(operation,
                                      algoritm,
                                      options,
                                      (keyData as NSData).bytes, keyLength,
                                      iv,
                                      data.bytes, data.length,
                                      cryptData.mutableBytes, cryptData.length,
                                      &numBytesEncrypted)
            
            if UInt32(cryptStatus) == UInt32(kCCSuccess) {
                cryptData.length = Int(numBytesEncrypted)
                let unencryptedMessage = String(data: cryptData as Data, encoding:String.Encoding.utf8)
                return unencryptedMessage
            }
            else {
                return nil
            }
        }
        return nil
}

}
