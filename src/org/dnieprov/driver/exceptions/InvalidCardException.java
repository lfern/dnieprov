/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.dnieprov.driver.exceptions;

/**
 *
 * @author luis
 */
public class InvalidCardException extends Exception{

    public InvalidCardException(Throwable cause) {
        super(cause);
    }

    public InvalidCardException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidCardException(String message) {
        super(message);
    }

    public InvalidCardException() {
    }
    
}
